// -*- c++-mode -*-
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <event2/bufferevent.h>

#include "ConnectionOptions.h"

using namespace std;

class Connection;

class Protocol {
public:
  Protocol(options_t _opts, Connection* _conn, bufferevent* _bev):
    opts(_opts), conn(_conn), bev(_bev) {};
  ~Protocol() {};

  virtual bool setup_connection_w() = 0;
  virtual bool setup_connection_r(evbuffer* input) = 0;
  // =e
  virtual int  get_request(const char* key, uint32_t id) = 0;
  virtual int  set_request(const char* key, const char* value, int len, uint32_t id) = 0;
  virtual uint32_t handle_response(evbuffer* input, bool &done) = 0;
  //virtual bool handle_response(evbuffer* input, bool &done) = 0;
  //

protected:
  options_t    opts;
  Connection*  conn;
  bufferevent* bev;
};

class ProtocolAscii : public Protocol {
public:
  ProtocolAscii(options_t opts, Connection* conn, bufferevent* bev):
    Protocol(opts, conn, bev) {
    read_state = IDLE;
  };

  ~ProtocolAscii() {};

  virtual bool setup_connection_w() { return true; }
  virtual bool setup_connection_r(evbuffer* input) { return true; }
  // =e
  virtual int  get_request(const char* key, uint32_t id);
  virtual int  set_request(const char* key, const char* value, int len, uint32_t id);
  //virtual bool handle_response(evbuffer* input, bool &done);
  virtual uint32_t handle_response(evbuffer* input, bool &done);
  //

private:
  enum read_fsm {
    IDLE,
    WAITING_FOR_GET,
    WAITING_FOR_GET_DATA,
    WAITING_FOR_END,
  };

  read_fsm read_state;
  int data_length;
};

class ProtocolBinary : public Protocol {
public:
  ProtocolBinary(options_t opts, Connection* conn, bufferevent* bev):
    Protocol(opts, conn, bev) {};
  ~ProtocolBinary() {};

  virtual bool setup_connection_w();
  virtual bool setup_connection_r(evbuffer* input);
  virtual int  get_request(const char* key, uint32_t id);
  virtual int  set_request(const char* key, const char* value, int len, uint32_t id);
  // =e
  //virtual bool handle_response(evbuffer* input, bool &done);
  virtual uint32_t handle_response(evbuffer* input, bool &done);
  //
};

#endif
