/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#ifndef SRSEPC_NAS_H
#define SRSEPC_NAS_H

#include "srsran/asn1/gtpc_ies.h"
#include "srsran/asn1/liblte_mme.h"
#include "srsran/common/buffer_pool.h"
#include "srsran/common/security.h"
#include "srsran/interfaces/epc_interfaces.h"
#include "srsran/srslog/srslog.h"
#include <netinet/sctp.h>

namespace srsepc {

static const uint8_t MAX_ERABS_PER_UE = 16;

// MME EMM states (3GPP 24.301 v10.0.0, section 5.1.3.4)
typedef enum {
  EMM_STATE_DEREGISTERED = 0,
  EMM_STATE_COMMON_PROCEDURE_INITIATED,
  EMM_STATE_REGISTERED,
  EMM_STATE_DEREGISTERED_INITIATED,
  EMM_STATE_N_ITEMS,
} emm_state_t;
static const char emm_state_text[EMM_STATE_N_ITEMS][100] = {"DEREGISTERED",
                                                            "COMMON PROCEDURE INITIATED",
                                                            "REGISTERED",
                                                            "DEREGISTERED INITIATED"};

// MME ECM states (3GPP 23.401 v10.0.0, section 4.6.3)
typedef enum {
  ECM_STATE_IDLE = 0,
  ECM_STATE_CONNECTED,
  ECM_STATE_N_ITEMS,
} ecm_state_t;
static const char ecm_state_text[ECM_STATE_N_ITEMS][100] = {"IDLE", "CONNECTED"};

/*
// MME ESM states (3GPP 23.401 v10.0.0, section 4.6.3)
typedef enum {
  ESM_BEARER_CONTEXT_INACTIVE = 0,
  ESM_BEARER_CONTEXT_ACTIVE_PENDING,
  ESM_BEARER_CONTEXT_ACTIVE,
  ESM_BEARER_CONTEXT_INACTIVE_PENDING,
  ESM_BEARER_CONTEXT_MODIFY_PENDING,
  ESM_BEARER_PROCEDURE_TRANSACTION_INACTIVE,
  ESM_BEARER_PROCEDURE_TRANSACTION_PENDING,
  ESM_STATE_N_ITEMS,
} esm_state_t;
static const char esm_state_text[ESM_STATE_N_ITEMS][100] = {"CONTEXT INACTIVE",
                                                            "CONTEXT ACTIVE PENDING",
                                                            "CONTEXT ACTIVE",
                                                            "CONTEXT_INACTIVE_PENDING",
                                                            "CONTEXT_MODIFY_PENDING",
                                                            "PROCEDURE_TRANSACTION_INACTIVE"
                                                            "PROCEDURE_TRANSACTION_PENDING"};
*/
typedef enum { ERAB_DEACTIVATED, ERAB_CTX_REQUESTED, ERAB_CTX_SETUP, ERAB_ACTIVE } esm_state_t;

/*
 * EMM, ECM, ESM and EPS Security context definitions
 */
typedef struct {
  uint64_t               imsi;
  emm_state_t            state;
  uint8_t                procedure_transaction_id;
  uint8_t                attach_type;
  struct in_addr         ue_ip;
  srsran::gtpc_f_teid_ie sgw_ctrl_fteid;
} emm_ctx_t;

typedef struct {
  ecm_state_t            state;
  uint32_t               enb_ue_s1ap_id;
  uint32_t               mme_ue_s1ap_id;
  struct sctp_sndrcvinfo enb_sri;
  bool                   eit;
} ecm_ctx_t;

typedef struct {
  uint8_t                                erab_id;
  esm_state_t                            state;
  uint8_t                                qci;
  srsran::gtpc_f_teid_ie                 enb_fteid;
  srsran::gtpc_f_teid_ie                 sgw_s1u_fteid;
  srsran::gtpc_pdn_address_allocation_ie pdn_addr_alloc;
} esm_ctx_t;

typedef struct {
  uint8_t                                 eksi;
  uint8_t                                 k_asme[32];
  uint8_t                                 autn[16];
  uint8_t                                 rand[16];
  uint8_t                                 xres[16]; // minimum 6, maximum 16
  uint32_t                                dl_nas_count;
  uint32_t                                ul_nas_count;
  srsran::CIPHERING_ALGORITHM_ID_ENUM     cipher_algo;
  srsran::INTEGRITY_ALGORITHM_ID_ENUM     integ_algo;
  uint8_t                                 k_nas_enc[32];
  uint8_t                                 k_nas_int[32];
  uint8_t                                 k_enb[32];
  LIBLTE_MME_UE_NETWORK_CAPABILITY_STRUCT ue_network_cap;
  bool                                    ms_network_cap_present;
  LIBLTE_MME_MS_NETWORK_CAPABILITY_STRUCT ms_network_cap;
  LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT    guti;
  // --------------------------Fuzzing-------------------------
  uint8_t                                 k_asme_tmp[32];
} sec_ctx_t;

/*
 * NAS Initialization Arguments
 */
typedef struct {
  uint16_t                            mcc;
  uint16_t                            mnc;
  uint8_t                             mme_code;
  uint16_t                            mme_group;
  uint16_t                            tac;
  uint16_t                            paging_timer;
  std::string                         apn;
  std::string                         dns;
  std::string                         full_net_name;
  std::string                         short_net_name;
  srsran::CIPHERING_ALGORITHM_ID_ENUM cipher_algo;
  srsran::INTEGRITY_ALGORITHM_ID_ENUM integ_algo;
  bool                                request_imeisv;
  uint16_t                            lac;
  uint64_t                            ue_under_test_imsi; // For fuzzing
  bool                                enable_ue_state_fuzzing; // For fuzzing
} nas_init_t;

typedef struct {
  s1ap_interface_nas* s1ap;
  gtpc_interface_nas* gtpc;
  hss_interface_nas*  hss;
  mme_interface_nas*  mme;
} nas_if_t;

class nas
{
public:
  nas(const nas_init_t& args, const nas_if_t& itf);
  void reset();

  /***********************
   * Initial UE messages *
   ***********************/
  // Attach request messages
  static bool handle_attach_request(uint32_t                enb_ue_s1ap_id,
                                    struct sctp_sndrcvinfo* enb_sri,
                                    srsran::byte_buffer_t*  nas_rx,
                                    const nas_init_t&       args,
                                    const nas_if_t&         itf);

  static bool handle_imsi_attach_request_unknown_ue(uint32_t                                    enb_ue_s1ap_id,
                                                    struct sctp_sndrcvinfo*                     enb_sri,
                                                    const LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT& attach_req,
                                                    const LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT& pdn_con_req,
                                                    const nas_init_t&                                     args,
                                                    const nas_if_t&                                       itf);

  static bool handle_imsi_attach_request_known_ue(nas*                                                  nas_ctx,
                                                  uint32_t                                              enb_ue_s1ap_id,
                                                  struct sctp_sndrcvinfo*                               enb_sri,
                                                  const LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT&           attach_req,
                                                  const LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT& pdn_con_req,
                                                  srsran::byte_buffer_t*                                nas_rx,
                                                  const nas_init_t&                                     args,
                                                  const nas_if_t&                                       itf);

  static bool handle_guti_attach_request_unknown_ue(uint32_t                                    enb_ue_s1ap_id,
                                                    struct sctp_sndrcvinfo*                     enb_sri,
                                                    const LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT& attach_req,
                                                    const LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT& pdn_con_req,
                                                    const nas_init_t&                                     args,
                                                    const nas_if_t&                                       itf);

  static bool handle_guti_attach_request_known_ue(nas*                                                  nas_ctx,
                                                  uint32_t                                              enb_ue_s1ap_id,
                                                  struct sctp_sndrcvinfo*                               enb_sri,
                                                  const LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT&           attach_req,
                                                  const LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT& pdn_con_req,
                                                  srsran::byte_buffer_t*                                nas_rx,
                                                  const nas_init_t&                                     args,
                                                  const nas_if_t&                                       itf);

  // Service request messages
  static bool handle_service_request(uint32_t                m_tmsi,
                                     uint32_t                enb_ue_s1ap_id,
                                     struct sctp_sndrcvinfo* enb_sri,
                                     srsran::byte_buffer_t*  nas_rx,
                                     const nas_init_t&       args,
                                     const nas_if_t&         itf);

  // Dettach request messages
  static bool handle_detach_request(uint32_t                m_tmsi,
                                    uint32_t                enb_ue_s1ap_id,
                                    struct sctp_sndrcvinfo* enb_sri,
                                    srsran::byte_buffer_t*  nas_rx,
                                    const nas_init_t&       args,
                                    const nas_if_t&         itf);

  // Tracking area update request messages
  static bool handle_tracking_area_update_request(uint32_t                m_tmsi,
                                                  uint32_t                enb_ue_s1ap_id,
                                                  struct sctp_sndrcvinfo* enb_sri,
                                                  srsran::byte_buffer_t*  nas_rx,
                                                  const nas_init_t&       args,
                                                  const nas_if_t&         itf);

  /* Uplink NAS messages handling */
  bool handle_attach_request(srsran::byte_buffer_t* nas_rx);
  bool handle_pdn_connectivity_request(srsran::byte_buffer_t* nas_rx);
  bool handle_authentication_response(srsran::byte_buffer_t* nas_rx, int flag);
  bool handle_security_mode_complete(srsran::byte_buffer_t* nas_rx);
  bool handle_attach_complete(srsran::byte_buffer_t* nas_rx);
  bool handle_esm_information_response(srsran::byte_buffer_t* nas_rx);
  bool handle_identity_response(srsran::byte_buffer_t* nas_rx);
  bool handle_tracking_area_update_request(srsran::byte_buffer_t* nas_rx);
  bool handle_authentication_failure(srsran::byte_buffer_t* nas_rx);
  bool handle_detach_request(srsran::byte_buffer_t* nas_rx);

  // Fuzzing
  bool handle_uplink_nas_transport(srsran::byte_buffer_t* nas_rx);
  bool handle_security_mode_reject(srsran::byte_buffer_t* nas_rx);
  bool handle_nas_emm_status(srsran::byte_buffer_t *nas_msg);
  bool handle_tracking_area_update_complete(srsran::byte_buffer_t* nas_rx);
  bool handle_guti_reallocation_complete(srsran::byte_buffer_t* nas_rx);

  /* Downlink NAS messages packing */
  bool pack_authentication_request(srsran::byte_buffer_t* nas_buffer);
  bool pack_authentication_reject(srsran::byte_buffer_t* nas_buffer);
  bool pack_security_mode_command(srsran::byte_buffer_t* nas_buffer);
  bool pack_esm_information_request(srsran::byte_buffer_t* nas_buffer);
  bool pack_identity_request(srsran::byte_buffer_t* nas_buffer);
  bool pack_emm_information(srsran::byte_buffer_t* nas_buffer);
  bool pack_service_reject(srsran::byte_buffer_t* nas_buffer, uint8_t emm_cause);
  bool pack_tracking_area_update_reject(srsran::byte_buffer_t* nas_buffer, uint8_t emm_cause);
  bool pack_attach_accept(srsran::byte_buffer_t* nas_buffer);
  bool pack_detach_request(srsran::byte_buffer_t* nas_buffer, int security_header_type, int cipher, int intergrity);

  // Fuzzing
  bool pack_authentication_request_custom(srsran::byte_buffer_t* nas_buffer, int cipher, int integrity, int replay, int seperation_bit, int sqn, int security_header_type);
  bool pack_security_mode_command_custom(srsran::byte_buffer_t* nas_buffer, int cipher, int integrity, int auth_parameter, int hash_mme, int eia, int eea, int security_header_type);
  bool pack_guti_reallocation_request_custom(srsran::byte_buffer_t* nas_buffer, int cipher, int integrity, int replay, int security_header_type);
  bool pack_identity_request_custom(srsran::byte_buffer_t* nas_buffer, int cipher, int integrity, int replay, int identification_parameter, int security_header_type);
  bool pack_dl_nas_transport_custom(srsran::byte_buffer_t* nas_buffer, int cipher, int integrity, int replay, int security_header_type);
  bool pack_attach_accept_custom(srsran::byte_buffer_t* nas_buffer, int cipher, int integrity, int replay, int security_header_type);
  // TODO: finish implementation of the following functions
  bool pack_service_reject_custom(srsran::byte_buffer_t* nas_buffer, uint8_t emm_cause, int security_header_type);
  bool pack_attach_reject_custom(srsran::byte_buffer_t* nas_buffer, uint8_t emm_cause);
  // Can detach request be sent from MME to UE?

  /* Security functions */
  bool integrity_check(srsran::byte_buffer_t* pdu, bool warn_failure = true);
  bool short_integrity_check(srsran::byte_buffer_t* pdu);
  void integrity_generate(srsran::byte_buffer_t* pdu, uint8_t* mac);
  void cipher_decrypt(srsran::byte_buffer_t* pdu);
  void cipher_encrypt(srsran::byte_buffer_t* pdu);
  void cipher_encrypt_null(srsran::byte_buffer_t* pdu); // fuzzing

  /*Timer functions*/
  bool start_timer(enum nas_timer_type type);
  bool expire_timer(enum nas_timer_type type);

  /* UE Context */
  emm_ctx_t m_emm_ctx                   = {};
  ecm_ctx_t m_ecm_ctx                   = {};
  esm_ctx_t m_esm_ctx[MAX_ERABS_PER_UE] = {};
  sec_ctx_t m_sec_ctx                   = {};

  //============================ Fuzzing ======================
  bool handle_statelearner_query_identity_request_custom(int cipher, int integrity, int replay, int identification_parameter, int security_header_type);
  bool handle_statelearner_query_authentication_request_custom(int cipher, int integrity, int replay, int seperation_bit, int sqn, int security_header_type);
  bool handle_statelearner_query_security_mode_command_custom(int cipher, int integrity, int replay, int auth_parameter, int eia, int eea, int security_header_type);
  bool handle_statelearner_query_attach_accept_custom(int cipher, int integrity, int replay, int security_header_type);
  bool handle_statelearner_query_guti_rellocation_custom(int cipher, int integrity, int replay, int security_header_type);
  bool handle_statelearner_query_dl_nas_transport_custom(int cipher, int integrity, int replay, int security_header_type);
  bool handle_statelearner_query_service_reject_custom(int emm_cause, int security_header_type);
  bool handle_statelearner_query_attach_reject_custom(int emm_cause);
  bool handle_statelearner_query_authentication_reject_custom();
  // emm_information (not sure if need)
  bool handle_statelearner_query_emm_information();
  bool handle_statelearner_query_detach_request_custom(int integrity, int cipher, int security_header_type);
  // bool handle_statelearner_query_detach_request_custom(int integrity, int cipher, int reattach_required, int security_header_type, int emm_cause);
  bool handle_statelearner_query_reset_attach_accept_setup();
  bool handle_statelearner_query_authentication_request();
  bool handle_statelearner_query_attach_accept_single();
  bool handle_statelearner_query_security_mode_command();
  bool handle_statelearner_query_identity_request();

private:
  srslog::basic_logger& m_logger = srslog::fetch_basic_logger("NAS");
  // srsran::byte_buffer_pool*  m_pool = nullptr;
  gtpc_interface_nas*   m_gtpc   = nullptr;
  s1ap_interface_nas*   m_s1ap   = nullptr;
  hss_interface_nas*    m_hss    = nullptr;
  mme_interface_nas*    m_mme    = nullptr;

  uint16_t    m_mcc       = 0;
  uint16_t    m_mnc       = 0;
  uint16_t    m_mme_group = 0;
  uint16_t    m_mme_code  = 0;
  uint16_t    m_tac       = 0;
  std::string m_apn;
  std::string m_dns;
  std::string m_full_net_name;
  std::string m_short_net_name;
  bool        m_request_imeisv = false;
  uint16_t    m_lac            = 0;

  uint64_t m_ue_under_test_imsi = 0; // Fuzzing
  bool m_enable_ue_state_fuzzing = false; // Fuzzing

  // Timers timeout values
  uint16_t m_t3413 = 0;

  // Timer functions
  bool start_t3413();
  bool expire_t3413();
};

} // namespace srsepc
#endif // SRSEPC_NAS_H
