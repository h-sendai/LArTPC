// -*- C++ -*-
/*!
 * @file 
 * @brief
 * @date
 * @author
 *
 */

#ifndef LARTPCREADER_H
#define LARTPCREADER_H

#include "DaqComponentBase.h"
#include "logUtil.h"

#include <daqmw/Sock.h>

using namespace RTC;

class LArTpcReader
    : public DAQMW::DaqComponentBase
{
public:
    LArTpcReader(RTC::Manager* manager);
    ~LArTpcReader();

    // The initialize action (on CREATED->ALIVE transition)
    // former rtc_init_entry()
    virtual RTC::ReturnCode_t onInitialize();

    // The execution action that is invoked periodically
    // former rtc_active_do()
    virtual RTC::ReturnCode_t onExecute(RTC::UniqueId ec_id);

private:
    TimedOctetSeq          m_out_data;
    OutPort<TimedOctetSeq> m_OutPort;

private:
    int daq_dummy();
    int daq_configure();
    int daq_unconfigure();
    int daq_start();
    int daq_run();
    int daq_stop();
    int daq_pause();
    int daq_resume();

    int parse_params(::NVList* list);
    int read_data_from_detectors();
    int set_data(unsigned int data_byte_size);
    int write_OutPort();
    int get_data_length(unsigned char *buf, int len);

    DAQMW::Sock* m_sock;               /// socket for data server

    static const int EVENT_BYTE_SIZE  = 8;    // event byte size
    static const int SEND_BUFFER_SIZE = 1024; //
    static const int MAX_BUFFER_SIZE = 1024*1024; //
    static const int HEADER_SIZE = 16;
    unsigned char m_data[MAX_BUFFER_SIZE];
    unsigned int  m_recv_byte_size;

    BufferStatus m_out_status;

    int m_srcPort;                        /// Port No. of data server
    std::string m_srcAddr;                /// IP addr. of data server

    bool m_debug;
};


extern "C"
{
    void LArTpcReaderInit(RTC::Manager* manager);
};

#endif // LARTPCREADER_H
