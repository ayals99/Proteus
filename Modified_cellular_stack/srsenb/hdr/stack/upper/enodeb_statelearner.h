//
// Created by rafiul on 9/11/19.
//

#ifndef SRSRAN_ENODEB_STATELEARNER_H
#define SRSRAN_ENODEB_STATELEARNER_H

#include "srsran/common/buffer_pool.h"
#include "srsran/common/threads.h"
#include "srsran/interfaces/enb_s1ap_interfaces.h"


namespace srsenb
{
    class enodeb_statelearner:
            public enodeb_statelearner_interface_s1ap,
            public srsran::thread
    {
    public:
        // static enodeb_statelearner* get_instance(void);
        // static void cleanup(void);
        enodeb_statelearner();
        int init(s1ap_interface_enodeb_statelearner *s1ap_);
        void stop();
        static enodeb_statelearner* get_instance(void);
        // server
        int statelearner_listen();
        int get_enodeb_statelearner();

        //client
        //bool connect_statelearner();
        bool notify_response(uint8_t *msg, uint16_t len);
        void run_thread();

    private:
        srsran::byte_buffer_pool   *m_pool;
        static enodeb_statelearner *m_instance;

        s1ap_interface_enodeb_statelearner* m_s1ap;

        in_addr_t m_enodeb_statelearner_ip;
        int m_enodeb_statelearner_sock;

        bool running = false;
        bool statelearner_connected       = false;
    };

}


#endif //SRSLTE_ENODEB_STATELEARNER_H
