#include <netinet/tcp.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>

#include "config.h"

#include "Connection.h"
#include "distributions.h"
#include "Generator.h"
#include "mutilate.h"
#include "binary_protocol.h"
#include "util.h"

// =e XXX
// This table represents a non real load which decays from 1M RPS to 20k RPS
// range: [50000 : 1M] rps
// use this table with -f flag and -i exponential:1000000
double decaying_table[24]{1953, 1855, 1757, 1660, 1562, 1464, 1367, 1269, 1171, 1171, 1074, 976.5, 878, 780, 683, 683,  586, 489, 392, 295, 199, 97.65, 80, 60};
// This table represents the facebook's ETC diurnal pattern
// range: [38000 : 73000] rps
// use this table with -f flag and -i fb_ia
double ia_table[24]{125.0, 117.18, 136.71, 126.953, 113.28, 101.56, 91.79, 74.21, 89.38, 95.70, 99.60, 82.03, 117.18, 125.0, 134.76, 140.62, 142.57, 138.67, 144.53, 142.51, 125.0, 119.14, 115.23, 97.65};
// This table represents Microsoft's trace with exponential interarrivals in Swaroop Kavalanekar's paper
// range: [33000 : 100000]
// use this table with -f flag and -i exponential:90000
double microsoft_table[24]{191.40, 195.31, 175.78, 146.48, 132.81, 126.95, 121.09, 126.95, 107.42, 87.89, 78.12, 70.31, 64.45, 70.31, 72.26, 74.21, 82.03, 89.84, 107.42, 97.65, 82.03, 80.07, 78.12, 74.21};
// This table represents NLANR's trace with exponential interarrivals in Swaroop Kavalanekar's paper
// range: [73000 : 99000]
// use this table with -f flag and -i exponential:90000
double nlanr_table[24] {146.48, 144.53, 142.57, 148.43, 160.15, 171.87, 177.73, 185.54, 181.64, 175.78, 183.59, 181.64, 179.68, 175.78, 181.64, 185.54, 193.35,185.54, 173.82, 171.87, 169.92, 166.01, 162.10};
//double scales[24]{16.2868, 15.8937, 15.6345, 15.7003, 16.3231, 17.5157, 18.6748, 19.5114, 20.2050, 20.2915, 19.5577, 18.2294, 16.2159, 15.6716, 15.2904, 15.2033, 14.9533, 15.1381, 15.3210, 15.3848, 15.7502, 16.0205, 16.3238};
//double shapes[24]{0.155280, 0.141368, 0.137579, 0.142382, 0.160706, 0.181278, 0.196885, 0.202396, 0.201637, 0.193764, 0.178386, 0.161636, 0.140461, 0.119242, 0.104535, 0.094286, 0.096963, 0.098510, 0.096155, 0.094156, 0.100365, 0.111921, 0.131946, 0.147258};
//

/**
 * Create a new connection to a server endpoint.
 */
Connection::Connection(struct event_base *_base, struct evdns_base *_evdns,
                       string _hostname, string _port, options_t _options,
                       bool sampling) : start_time(0), stats(sampling), options(_options),
                                        hostname(_hostname), port(_port), base(_base), evdns(_evdns)
{
  valuesize = createGenerator(options.valuesize);
  keysize = createGenerator(options.keysize);
  keygen = new KeyGenerator(keysize, options.records);

  if (options.lambda <= 0)
  {
    iagen = createGenerator("0");
  }
  else
  {
    D("iagen = createGenerator(%s)", options.ia);
    iagen = createGenerator(options.ia);
    iagen->set_lambda(options.lambda);
  }

  read_state = INIT_READ;
  write_state = INIT_WRITE;

  last_tx = last_rx = 0.0;

  bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  bufferevent_setcb(bev, bev_read_cb, bev_write_cb, bev_event_cb, this);
  bufferevent_enable(bev, EV_READ | EV_WRITE);

  if (options.binary)
  {
    prot = new ProtocolBinary(options, this, bev);
  }
  else
  {
    prot = new ProtocolAscii(options, this, bev);
  }

  if (bufferevent_socket_connect_hostname(bev, evdns, AF_UNSPEC,
                                          hostname.c_str(),
                                          atoi(port.c_str())))
  {
    DIE("bufferevent_socket_connect_hostname()");
  }

  timer = evtimer_new(base, timer_cb, this);

  // =e  XXX
  last_ia_change = 0;
  ia_pointer = 0;
  request_uid = 2;
  //
}

/**
 * Destroy a connection, performing cleanup.
 */
Connection::~Connection()
{
  event_free(timer);
  timer = NULL;
  // FIXME:  W("Drain op_q?");
  bufferevent_free(bev);

  delete iagen;
  delete keygen;
  delete keysize;
  delete valuesize;
}

/**
 * Reset the connection back to an initial, fresh state.
 */
void Connection::reset()
{
  // FIXME: Actually check the connection, drain all bufferevents, drain op_q.
  assert(op_queue.size() == 0);
  evtimer_del(timer);
  read_state = IDLE;
  write_state = INIT_WRITE;
  stats = ConnectionStats(stats.sampling);
}

/**
 * Set our event processing priority.
 */
void Connection::set_priority(int pri)
{
  if (bufferevent_priority_set(bev, pri))
  {
    DIE("bufferevent_set_priority(bev, %d) failed", pri);
  }
}

/**
 * Load any required test data onto the server.
 */
void Connection::start_loading()
{
  read_state = LOADING;
  loader_issued = loader_completed = 0;

  for (int i = 0; i < LOADER_CHUNK; i++)
  {
    if (loader_issued >= options.records)
      break;
    char key[256];
    int index = lrand48() % (1024 * 1024);
    string keystr = keygen->generate(loader_issued);
    strcpy(key, keystr.c_str());
    issue_set(key, &random_char[index], valuesize->generate());
    loader_issued++;
  }
}

/**
 * Issue either a get or set request to the server according to our probability distribution.
 */
void Connection::issue_something(double now)
{
  char key[256];
  // FIXME: generate key distribution here!
  string keystr = keygen->generate(lrand48() % options.records);
  strcpy(key, keystr.c_str());

  if (drand48() < options.update)
  {
    int index = lrand48() % (1024 * 1024);
    issue_set(key, &random_char[index], valuesize->generate(), now);
  }
  else
  {
    issue_get(key, now);
  }
}

/**
 * Issue a get request to the server.
 */
void Connection::issue_get(const char *key, double now)
{
  Operation op;
  int l;

#if HAVE_CLOCK_GETTIME
  op.start_time = get_time_accurate();
#else
  if (now == 0.0)
  {
#if USE_CACHED_TIME
    struct timeval now_tv;
    event_base_gettimeofday_cached(base, &now_tv);
    op.start_time = tv_to_double(&now_tv);
#else
    op.start_time = get_time();
#endif
  }
  else
  {
    op.start_time = now;
  }
#endif

  op.key = string(key);
  op.type = Operation::GET;
  op_queue.push(op);
  // =e
  request_times[request_uid] = op.start_time;
  //printf("id %u start is %f\n", request_uid, request_times[request_uid]);
  //

  if (read_state == IDLE)
    read_state = WAITING_FOR_GET;
  // =e
  l = prot->get_request(key, request_uid);
  request_uid++;
  //
  if (read_state != LOADING)
    stats.tx_bytes += l;
}

/**
 * Issue a set request to the server.
 */
void Connection::issue_set(const char *key, const char *value, int length,
                           double now)
{
  Operation op;
  int l;

#if HAVE_CLOCK_GETTIME
  op.start_time = get_time_accurate();
#else
  if (now == 0.0)
    op.start_time = get_time();
  else
    op.start_time = now;
#endif

  op.type = Operation::SET;
  op_queue.push(op);
  // =e
  request_times[request_uid] = op.start_time;
  request_uid++;
  //

  if (read_state == IDLE)
    read_state = WAITING_FOR_SET;
  // =e
  l = prot->set_request(key, value, length, request_uid);
  //
  if (read_state != LOADING)
    stats.tx_bytes += l;
}

/**
 * Return the oldest live operation in progress.
 */
void Connection::pop_op()
{
  assert(op_queue.size() > 0);

  op_queue.pop();

  if (read_state == LOADING)
    return;
  read_state = IDLE;

  // Advance the read state machine.
  if (op_queue.size() > 0)
  {
    Operation &op = op_queue.front();
    switch (op.type)
    {
    case Operation::GET:
      read_state = WAITING_FOR_GET;
      break;
    case Operation::SET:
      read_state = WAITING_FOR_SET;
      break;
    default:
      DIE("Not implemented.");
    }
  }
}

/**
 * Finish up (record stats) an operation that just returned from the
 * server.
 */
// =e
void Connection::finish_op(Operation *op, uint32_t id)
{
  double now;
#if USE_CACHED_TIME
  struct timeval now_tv;
  event_base_gettimeofday_cached(base, &now_tv);
  now = tv_to_double(&now_tv);
#else
  now = get_time();
#endif
#if HAVE_CLOCK_GETTIME
  op->end_time = get_time_accurate();
#else
  op->end_time = now;
#endif
  // =e
  if (id > 1)
  {
    //printf("id %u %f %f\n", id, op->start_time, request_times[id]);
    op->start_time = request_times[id];
  }
  sampler++;
  if(sampler >= 100){
    sampler = 0;
    switch (op->type)
    {
    case Operation::GET:
      stats.log_get(*op);
      break;
    case Operation::SET:
      stats.log_set(*op);
      break;
    default:
      DIE("Not implemented.");
    }
  }

  //

  last_rx = now;
  pop_op();
  drive_write_machine();
}

/**
 * Check if our testing is done and we should exit.
 */
bool Connection::check_exit_condition(double now)
{
  if (read_state == INIT_READ)
    return false;
  if (now == 0.0)
    now = get_time();
  if (now > start_time + options.time)
    return true;
  if (options.loadonly && read_state == IDLE)
    return true;
  return false;
}

/**
 * Handle new connection and error events.
 */
void Connection::event_callback(short events)
{
  if (events & BEV_EVENT_CONNECTED)
  {
    D("Connected to %s:%s.", hostname.c_str(), port.c_str());
    int fd = bufferevent_getfd(bev);
    if (fd < 0)
      DIE("bufferevent_getfd");

    if (!options.no_nodelay)
    {
      int one = 1;
      if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                     (void *)&one, sizeof(one)) < 0)
        DIE("setsockopt()");
    }

    read_state = CONN_SETUP;
    if (prot->setup_connection_w())
    {
      read_state = IDLE;
    }
  }
  else if (events & BEV_EVENT_ERROR)
  {
    int err = bufferevent_socket_get_dns_error(bev);
    if (err)
      DIE("DNS error: %s", evutil_gai_strerror(err));
    DIE("BEV_EVENT_ERROR: %s", strerror(errno));
  }
  else if (events & BEV_EVENT_EOF)
  {
    DIE("Unexpected EOF from server.");
  }
}

/**
 * Request generation loop. Determines whether or not to issue a new command,
 * based on timer events.
 *
 * Note that this function loops. Be wary of break vs. return.
 */
void Connection::drive_write_machine(double now)
{
  if (now == 0.0)
    now = get_time();

  double delay;
  struct timeval tv;

  if (check_exit_condition(now))
    return;
  // =e
  if (options.diurnal)
  {
    if (last_ia_change == 0)
      last_ia_change = now;
    if (now - last_ia_change > options.diurnal)
    {
      last_ia_change = now;
      ia_pointer = (ia_pointer + 1) % 24;
      double new_lambda = decaying_table[ia_pointer];  // =e change table name here
      iagen->set_lambda(new_lambda);
      //iagen->set_attrs(0.0, scales[ia_pointer], shapes[ia_pointer]);
      D("iagen = changing rate to (%f)", new_lambda*512);
    }
  }
  //

  while (1)
  {
    switch (write_state)
    {
    case INIT_WRITE:
      delay = iagen->generate();
      next_time = now + delay;
      double_to_tv(delay, &tv);
      evtimer_add(timer, &tv);
      write_state = WAITING_FOR_TIME;
      break;

    case ISSUING:
      if (op_queue.size() >= (size_t)options.depth)
      {
        write_state = WAITING_FOR_OPQ;
        return;
      }
      else if (now < next_time)
      {
        write_state = WAITING_FOR_TIME;
        break; // We want to run through the state machine one more time
               // to make sure the timer is armed.
      }
      else if (options.moderate && now < last_rx + 0.00025)
      {
        write_state = WAITING_FOR_TIME;
        if (!event_pending(timer, EV_TIMEOUT, NULL))
        {
          delay = last_rx + 0.00025 - now;
          double_to_tv(delay, &tv);
          evtimer_add(timer, &tv);
        }
        return;
      }

      issue_something(now);
      last_tx = now;
      stats.log_op(op_queue.size());
      next_time += iagen->generate();

      if (options.skip && options.lambda > 0.0 &&
          now - next_time > 0.005000 &&
          op_queue.size() >= (size_t)options.depth)
      {

        while (next_time < now - 0.004000)
        {
          stats.skips++;
          next_time += iagen->generate();
        }
      }
      break;

    case WAITING_FOR_TIME:
      if (now < next_time)
      {
        if (!event_pending(timer, EV_TIMEOUT, NULL))
        {
          delay = next_time - now;
          double_to_tv(delay, &tv);
          evtimer_add(timer, &tv);
        }
        return;
      }
      write_state = ISSUING;
      break;

    case WAITING_FOR_OPQ:
      if (op_queue.size() >= (size_t)options.depth)
        return;
      write_state = ISSUING;
      break;

    default:
      DIE("Not implemented");
    }
  }
}

/**
 * Handle incoming data (responses).
 */
void Connection::read_callback()
{
  struct evbuffer *input = bufferevent_get_input(bev);

  Operation *op = NULL;
  bool done; //, full_read;
  // =e
  uint32_t rid;
  //

  if (op_queue.size() == 0)
    V("Spurious read callback.");

  while (1)
  {
    if (op_queue.size() > 0)
      op = &op_queue.front();

    switch (read_state)
    {
    case INIT_READ:
      DIE("event from uninitialized connection");
    case IDLE:
      return; // We munched all the data we expected?

    case WAITING_FOR_GET:
      assert(op_queue.size() > 0);
      // =e
      rid = prot->handle_response(input, done);

      if (!rid)
      {
        //
        return;
      }
      else if (done)
      {
        finish_op(op, rid); // sets read_state = IDLE
      }
      break;

    case WAITING_FOR_SET:
      assert(op_queue.size() > 0);
      // =e
      rid = prot->handle_response(input, done);
      if (!rid)
        return;
      //
      finish_op(op, rid);
      break;

    case LOADING:
      assert(op_queue.size() > 0);
      if (!prot->handle_response(input, done))
        return;
      loader_completed++;
      pop_op();

      if (loader_completed == options.records)
      {
        D("Finished loading.");
        read_state = IDLE;
      }
      else
      {
        while (loader_issued < loader_completed + LOADER_CHUNK)
        {
          if (loader_issued >= options.records)
            break;

          char key[256];
          string keystr = keygen->generate(loader_issued);
          strcpy(key, keystr.c_str());
          int index = lrand48() % (1024 * 1024);
          issue_set(key, &random_char[index], valuesize->generate());

          loader_issued++;
        }
      }

      break;

    case CONN_SETUP:
      assert(options.binary);
      if (!prot->setup_connection_r(input))
        return;
      read_state = IDLE;
      break;

    default:
      DIE("not implemented");
    }
  }
}

/**
 * Callback called when write requests finish.
 */
void Connection::write_callback() {}

/**
 * Callback for timer timeouts.
 */
void Connection::timer_callback() { drive_write_machine(); }

/* The follow are C trampolines for libevent callbacks. */
void bev_event_cb(struct bufferevent *bev, short events, void *ptr)
{
  Connection *conn = (Connection *)ptr;
  conn->event_callback(events);
}

void bev_read_cb(struct bufferevent *bev, void *ptr)
{
  Connection *conn = (Connection *)ptr;
  conn->read_callback();
}

void bev_write_cb(struct bufferevent *bev, void *ptr)
{
  Connection *conn = (Connection *)ptr;
  conn->write_callback();
}

void timer_cb(evutil_socket_t fd, short what, void *ptr)
{
  Connection *conn = (Connection *)ptr;
  conn->timer_callback();
}
