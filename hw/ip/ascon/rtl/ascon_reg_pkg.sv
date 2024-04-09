// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// Register Package auto-generated by `reggen` containing data structure

package ascon_reg_pkg;

  // Param list
  parameter int NumRegsKey = 4;
  parameter int NumRegsNonce = 4;
  parameter int NumRegsData = 4;
  parameter int NumRegsTag = 4;
  parameter int NumAlerts = 2;

  // Address widths within the block
  parameter int BlockAw = 8;

  ////////////////////////////
  // Typedefs for registers //
  ////////////////////////////

  typedef struct packed {
    struct packed {
      logic        q;
      logic        qe;
    } fatal_fault;
    struct packed {
      logic        q;
      logic        qe;
    } recov_ctrl_update_err;
  } ascon_reg2hw_alert_test_reg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        qe;
  } ascon_reg2hw_key_share0_mreg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        qe;
  } ascon_reg2hw_key_share1_mreg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        qe;
  } ascon_reg2hw_nonce_share0_mreg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        qe;
  } ascon_reg2hw_nonce_share1_mreg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        qe;
  } ascon_reg2hw_data_in_share0_mreg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        qe;
  } ascon_reg2hw_data_in_share1_mreg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        qe;
  } ascon_reg2hw_tag_in_mreg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        re;
  } ascon_reg2hw_msg_out_mreg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        re;
  } ascon_reg2hw_tag_out_mreg_t;

  typedef struct packed {
    struct packed {
      logic        q;
      logic        qe;
    } no_ad;
    struct packed {
      logic        q;
      logic        qe;
    } no_msg;
    struct packed {
      logic        q;
      logic        qe;
    } masked_msg_input;
    struct packed {
      logic        q;
      logic        qe;
    } masked_ad_input;
    struct packed {
      logic        q;
      logic        qe;
    } sideload_key;
    struct packed {
      logic [2:0]  q;
      logic        qe;
    } operation;
  } ascon_reg2hw_ctrl_shadowed_reg_t;

  typedef struct packed {
    struct packed {
      logic        q;
      logic        qe;
    } force_data_overwrite;
    struct packed {
      logic        q;
      logic        qe;
    } manual_start_trigger;
  } ascon_reg2hw_ctrl_aux_shadowed_reg_t;

  typedef struct packed {
    struct packed {
      logic [4:0]  q;
      logic        qe;
    } valid_bytes;
    struct packed {
      logic [11:0] q;
      logic        qe;
    } data_type_last;
    struct packed {
      logic [11:0] q;
      logic        qe;
    } data_type_start;
  } ascon_reg2hw_block_ctrl_shadowed_reg_t;

  typedef struct packed {
    struct packed {
      logic        q;
    } wipe;
    struct packed {
      logic        q;
    } start;
  } ascon_reg2hw_trigger_reg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        qe;
  } ascon_reg2hw_fsm_state_reg_t;

  typedef struct packed {
    logic [31:0] d;
  } ascon_hw2reg_key_share0_mreg_t;

  typedef struct packed {
    logic [31:0] d;
  } ascon_hw2reg_key_share1_mreg_t;

  typedef struct packed {
    logic [31:0] d;
  } ascon_hw2reg_nonce_share0_mreg_t;

  typedef struct packed {
    logic [31:0] d;
  } ascon_hw2reg_nonce_share1_mreg_t;

  typedef struct packed {
    logic [31:0] d;
  } ascon_hw2reg_data_in_share0_mreg_t;

  typedef struct packed {
    logic [31:0] d;
  } ascon_hw2reg_data_in_share1_mreg_t;

  typedef struct packed {
    logic [31:0] d;
  } ascon_hw2reg_msg_out_mreg_t;

  typedef struct packed {
    logic [31:0] d;
  } ascon_hw2reg_tag_out_mreg_t;

  typedef struct packed {
    struct packed {
      logic        d;
      logic        de;
    } start;
    struct packed {
      logic        d;
      logic        de;
    } wipe;
  } ascon_hw2reg_trigger_reg_t;

  typedef struct packed {
    struct packed {
      logic        d;
      logic        de;
    } idle;
    struct packed {
      logic        d;
      logic        de;
    } stall;
    struct packed {
      logic        d;
      logic        de;
    } wait_edn;
    struct packed {
      logic        d;
      logic        de;
    } ascon_error;
    struct packed {
      logic        d;
      logic        de;
    } alert_recov_ctrl_update_err;
    struct packed {
      logic        d;
      logic        de;
    } alert_recov_ctrl_aux_update_err;
    struct packed {
      logic        d;
      logic        de;
    } alert_recov_block_ctrl_update_err;
    struct packed {
      logic        d;
      logic        de;
    } alert_fatal_fault;
  } ascon_hw2reg_status_reg_t;

  typedef struct packed {
    struct packed {
      logic [2:0]  d;
      logic        de;
    } data_type;
    struct packed {
      logic [1:0]  d;
      logic        de;
    } tag_comparison_valid;
  } ascon_hw2reg_output_valid_reg_t;

  typedef struct packed {
    logic [31:0] d;
  } ascon_hw2reg_fsm_state_reg_t;

  typedef struct packed {
    struct packed {
      logic        d;
      logic        de;
    } no_key;
    struct packed {
      logic        d;
      logic        de;
    } no_nonce;
    struct packed {
      logic        d;
      logic        de;
    } wrong_order;
    struct packed {
      logic        d;
      logic        de;
    } flag_input_missmatch;
  } ascon_hw2reg_error_reg_t;

  // Register -> HW type
  typedef struct packed {
    ascon_reg2hw_alert_test_reg_t alert_test; // [1276:1273]
    ascon_reg2hw_key_share0_mreg_t [3:0] key_share0; // [1272:1141]
    ascon_reg2hw_key_share1_mreg_t [3:0] key_share1; // [1140:1009]
    ascon_reg2hw_nonce_share0_mreg_t [3:0] nonce_share0; // [1008:877]
    ascon_reg2hw_nonce_share1_mreg_t [3:0] nonce_share1; // [876:745]
    ascon_reg2hw_data_in_share0_mreg_t [3:0] data_in_share0; // [744:613]
    ascon_reg2hw_data_in_share1_mreg_t [3:0] data_in_share1; // [612:481]
    ascon_reg2hw_tag_in_mreg_t [3:0] tag_in; // [480:349]
    ascon_reg2hw_msg_out_mreg_t [3:0] msg_out; // [348:217]
    ascon_reg2hw_tag_out_mreg_t [3:0] tag_out; // [216:85]
    ascon_reg2hw_ctrl_shadowed_reg_t ctrl_shadowed; // [84:71]
    ascon_reg2hw_ctrl_aux_shadowed_reg_t ctrl_aux_shadowed; // [70:67]
    ascon_reg2hw_block_ctrl_shadowed_reg_t block_ctrl_shadowed; // [66:35]
    ascon_reg2hw_trigger_reg_t trigger; // [34:33]
    ascon_reg2hw_fsm_state_reg_t fsm_state; // [32:0]
  } ascon_reg2hw_t;

  // HW -> register type
  typedef struct packed {
    ascon_hw2reg_key_share0_mreg_t [3:0] key_share0; // [1090:963]
    ascon_hw2reg_key_share1_mreg_t [3:0] key_share1; // [962:835]
    ascon_hw2reg_nonce_share0_mreg_t [3:0] nonce_share0; // [834:707]
    ascon_hw2reg_nonce_share1_mreg_t [3:0] nonce_share1; // [706:579]
    ascon_hw2reg_data_in_share0_mreg_t [3:0] data_in_share0; // [578:451]
    ascon_hw2reg_data_in_share1_mreg_t [3:0] data_in_share1; // [450:323]
    ascon_hw2reg_msg_out_mreg_t [3:0] msg_out; // [322:195]
    ascon_hw2reg_tag_out_mreg_t [3:0] tag_out; // [194:67]
    ascon_hw2reg_trigger_reg_t trigger; // [66:63]
    ascon_hw2reg_status_reg_t status; // [62:47]
    ascon_hw2reg_output_valid_reg_t output_valid; // [46:40]
    ascon_hw2reg_fsm_state_reg_t fsm_state; // [39:8]
    ascon_hw2reg_error_reg_t error; // [7:0]
  } ascon_hw2reg_t;

  // Register offsets
  parameter logic [BlockAw-1:0] ASCON_ALERT_TEST_OFFSET = 8'h 0;
  parameter logic [BlockAw-1:0] ASCON_KEY_SHARE0_0_OFFSET = 8'h 4;
  parameter logic [BlockAw-1:0] ASCON_KEY_SHARE0_1_OFFSET = 8'h 8;
  parameter logic [BlockAw-1:0] ASCON_KEY_SHARE0_2_OFFSET = 8'h c;
  parameter logic [BlockAw-1:0] ASCON_KEY_SHARE0_3_OFFSET = 8'h 10;
  parameter logic [BlockAw-1:0] ASCON_KEY_SHARE1_0_OFFSET = 8'h 14;
  parameter logic [BlockAw-1:0] ASCON_KEY_SHARE1_1_OFFSET = 8'h 18;
  parameter logic [BlockAw-1:0] ASCON_KEY_SHARE1_2_OFFSET = 8'h 1c;
  parameter logic [BlockAw-1:0] ASCON_KEY_SHARE1_3_OFFSET = 8'h 20;
  parameter logic [BlockAw-1:0] ASCON_NONCE_SHARE0_0_OFFSET = 8'h 24;
  parameter logic [BlockAw-1:0] ASCON_NONCE_SHARE0_1_OFFSET = 8'h 28;
  parameter logic [BlockAw-1:0] ASCON_NONCE_SHARE0_2_OFFSET = 8'h 2c;
  parameter logic [BlockAw-1:0] ASCON_NONCE_SHARE0_3_OFFSET = 8'h 30;
  parameter logic [BlockAw-1:0] ASCON_NONCE_SHARE1_0_OFFSET = 8'h 34;
  parameter logic [BlockAw-1:0] ASCON_NONCE_SHARE1_1_OFFSET = 8'h 38;
  parameter logic [BlockAw-1:0] ASCON_NONCE_SHARE1_2_OFFSET = 8'h 3c;
  parameter logic [BlockAw-1:0] ASCON_NONCE_SHARE1_3_OFFSET = 8'h 40;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_SHARE0_0_OFFSET = 8'h 44;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_SHARE0_1_OFFSET = 8'h 48;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_SHARE0_2_OFFSET = 8'h 4c;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_SHARE0_3_OFFSET = 8'h 50;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_SHARE1_0_OFFSET = 8'h 54;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_SHARE1_1_OFFSET = 8'h 58;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_SHARE1_2_OFFSET = 8'h 5c;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_SHARE1_3_OFFSET = 8'h 60;
  parameter logic [BlockAw-1:0] ASCON_TAG_IN_0_OFFSET = 8'h 64;
  parameter logic [BlockAw-1:0] ASCON_TAG_IN_1_OFFSET = 8'h 68;
  parameter logic [BlockAw-1:0] ASCON_TAG_IN_2_OFFSET = 8'h 6c;
  parameter logic [BlockAw-1:0] ASCON_TAG_IN_3_OFFSET = 8'h 70;
  parameter logic [BlockAw-1:0] ASCON_MSG_OUT_0_OFFSET = 8'h 74;
  parameter logic [BlockAw-1:0] ASCON_MSG_OUT_1_OFFSET = 8'h 78;
  parameter logic [BlockAw-1:0] ASCON_MSG_OUT_2_OFFSET = 8'h 7c;
  parameter logic [BlockAw-1:0] ASCON_MSG_OUT_3_OFFSET = 8'h 80;
  parameter logic [BlockAw-1:0] ASCON_TAG_OUT_0_OFFSET = 8'h 84;
  parameter logic [BlockAw-1:0] ASCON_TAG_OUT_1_OFFSET = 8'h 88;
  parameter logic [BlockAw-1:0] ASCON_TAG_OUT_2_OFFSET = 8'h 8c;
  parameter logic [BlockAw-1:0] ASCON_TAG_OUT_3_OFFSET = 8'h 90;
  parameter logic [BlockAw-1:0] ASCON_CTRL_SHADOWED_OFFSET = 8'h 94;
  parameter logic [BlockAw-1:0] ASCON_CTRL_AUX_SHADOWED_OFFSET = 8'h 98;
  parameter logic [BlockAw-1:0] ASCON_CTRL_AUX_REGWEN_OFFSET = 8'h 9c;
  parameter logic [BlockAw-1:0] ASCON_BLOCK_CTRL_SHADOWED_OFFSET = 8'h a0;
  parameter logic [BlockAw-1:0] ASCON_TRIGGER_OFFSET = 8'h a4;
  parameter logic [BlockAw-1:0] ASCON_STATUS_OFFSET = 8'h a8;
  parameter logic [BlockAw-1:0] ASCON_OUTPUT_VALID_OFFSET = 8'h ac;
  parameter logic [BlockAw-1:0] ASCON_FSM_STATE_OFFSET = 8'h b0;
  parameter logic [BlockAw-1:0] ASCON_FSM_STATE_REGREN_OFFSET = 8'h b4;
  parameter logic [BlockAw-1:0] ASCON_ERROR_OFFSET = 8'h b8;

  // Reset values for hwext registers and their fields
  parameter logic [1:0] ASCON_ALERT_TEST_RESVAL = 2'h 0;
  parameter logic [0:0] ASCON_ALERT_TEST_RECOV_CTRL_UPDATE_ERR_RESVAL = 1'h 0;
  parameter logic [0:0] ASCON_ALERT_TEST_FATAL_FAULT_RESVAL = 1'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE0_0_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE0_0_KEY_SHARE0_0_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE0_1_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE0_1_KEY_SHARE0_1_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE0_2_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE0_2_KEY_SHARE0_2_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE0_3_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE0_3_KEY_SHARE0_3_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE1_0_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE1_0_KEY_SHARE1_0_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE1_1_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE1_1_KEY_SHARE1_1_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE1_2_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE1_2_KEY_SHARE1_2_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE1_3_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_KEY_SHARE1_3_KEY_SHARE1_3_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_NONCE_SHARE0_0_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_NONCE_SHARE0_1_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_NONCE_SHARE0_2_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_NONCE_SHARE0_3_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_NONCE_SHARE1_0_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_NONCE_SHARE1_1_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_NONCE_SHARE1_2_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_NONCE_SHARE1_3_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_DATA_IN_SHARE0_0_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_DATA_IN_SHARE0_1_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_DATA_IN_SHARE0_2_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_DATA_IN_SHARE0_3_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_DATA_IN_SHARE1_0_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_DATA_IN_SHARE1_1_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_DATA_IN_SHARE1_2_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_DATA_IN_SHARE1_3_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_MSG_OUT_0_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_MSG_OUT_1_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_MSG_OUT_2_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_MSG_OUT_3_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_TAG_OUT_0_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_TAG_OUT_1_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_TAG_OUT_2_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_TAG_OUT_3_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_FSM_STATE_RESVAL = 32'h 0;

  // Register index
  typedef enum int {
    ASCON_ALERT_TEST,
    ASCON_KEY_SHARE0_0,
    ASCON_KEY_SHARE0_1,
    ASCON_KEY_SHARE0_2,
    ASCON_KEY_SHARE0_3,
    ASCON_KEY_SHARE1_0,
    ASCON_KEY_SHARE1_1,
    ASCON_KEY_SHARE1_2,
    ASCON_KEY_SHARE1_3,
    ASCON_NONCE_SHARE0_0,
    ASCON_NONCE_SHARE0_1,
    ASCON_NONCE_SHARE0_2,
    ASCON_NONCE_SHARE0_3,
    ASCON_NONCE_SHARE1_0,
    ASCON_NONCE_SHARE1_1,
    ASCON_NONCE_SHARE1_2,
    ASCON_NONCE_SHARE1_3,
    ASCON_DATA_IN_SHARE0_0,
    ASCON_DATA_IN_SHARE0_1,
    ASCON_DATA_IN_SHARE0_2,
    ASCON_DATA_IN_SHARE0_3,
    ASCON_DATA_IN_SHARE1_0,
    ASCON_DATA_IN_SHARE1_1,
    ASCON_DATA_IN_SHARE1_2,
    ASCON_DATA_IN_SHARE1_3,
    ASCON_TAG_IN_0,
    ASCON_TAG_IN_1,
    ASCON_TAG_IN_2,
    ASCON_TAG_IN_3,
    ASCON_MSG_OUT_0,
    ASCON_MSG_OUT_1,
    ASCON_MSG_OUT_2,
    ASCON_MSG_OUT_3,
    ASCON_TAG_OUT_0,
    ASCON_TAG_OUT_1,
    ASCON_TAG_OUT_2,
    ASCON_TAG_OUT_3,
    ASCON_CTRL_SHADOWED,
    ASCON_CTRL_AUX_SHADOWED,
    ASCON_CTRL_AUX_REGWEN,
    ASCON_BLOCK_CTRL_SHADOWED,
    ASCON_TRIGGER,
    ASCON_STATUS,
    ASCON_OUTPUT_VALID,
    ASCON_FSM_STATE,
    ASCON_FSM_STATE_REGREN,
    ASCON_ERROR
  } ascon_id_e;

  // Register width information to check illegal writes
  parameter logic [3:0] ASCON_PERMIT [47] = '{
    4'b 0001, // index[ 0] ASCON_ALERT_TEST
    4'b 1111, // index[ 1] ASCON_KEY_SHARE0_0
    4'b 1111, // index[ 2] ASCON_KEY_SHARE0_1
    4'b 1111, // index[ 3] ASCON_KEY_SHARE0_2
    4'b 1111, // index[ 4] ASCON_KEY_SHARE0_3
    4'b 1111, // index[ 5] ASCON_KEY_SHARE1_0
    4'b 1111, // index[ 6] ASCON_KEY_SHARE1_1
    4'b 1111, // index[ 7] ASCON_KEY_SHARE1_2
    4'b 1111, // index[ 8] ASCON_KEY_SHARE1_3
    4'b 1111, // index[ 9] ASCON_NONCE_SHARE0_0
    4'b 1111, // index[10] ASCON_NONCE_SHARE0_1
    4'b 1111, // index[11] ASCON_NONCE_SHARE0_2
    4'b 1111, // index[12] ASCON_NONCE_SHARE0_3
    4'b 1111, // index[13] ASCON_NONCE_SHARE1_0
    4'b 1111, // index[14] ASCON_NONCE_SHARE1_1
    4'b 1111, // index[15] ASCON_NONCE_SHARE1_2
    4'b 1111, // index[16] ASCON_NONCE_SHARE1_3
    4'b 1111, // index[17] ASCON_DATA_IN_SHARE0_0
    4'b 1111, // index[18] ASCON_DATA_IN_SHARE0_1
    4'b 1111, // index[19] ASCON_DATA_IN_SHARE0_2
    4'b 1111, // index[20] ASCON_DATA_IN_SHARE0_3
    4'b 1111, // index[21] ASCON_DATA_IN_SHARE1_0
    4'b 1111, // index[22] ASCON_DATA_IN_SHARE1_1
    4'b 1111, // index[23] ASCON_DATA_IN_SHARE1_2
    4'b 1111, // index[24] ASCON_DATA_IN_SHARE1_3
    4'b 1111, // index[25] ASCON_TAG_IN_0
    4'b 1111, // index[26] ASCON_TAG_IN_1
    4'b 1111, // index[27] ASCON_TAG_IN_2
    4'b 1111, // index[28] ASCON_TAG_IN_3
    4'b 1111, // index[29] ASCON_MSG_OUT_0
    4'b 1111, // index[30] ASCON_MSG_OUT_1
    4'b 1111, // index[31] ASCON_MSG_OUT_2
    4'b 1111, // index[32] ASCON_MSG_OUT_3
    4'b 1111, // index[33] ASCON_TAG_OUT_0
    4'b 1111, // index[34] ASCON_TAG_OUT_1
    4'b 1111, // index[35] ASCON_TAG_OUT_2
    4'b 1111, // index[36] ASCON_TAG_OUT_3
    4'b 0001, // index[37] ASCON_CTRL_SHADOWED
    4'b 0001, // index[38] ASCON_CTRL_AUX_SHADOWED
    4'b 0001, // index[39] ASCON_CTRL_AUX_REGWEN
    4'b 1111, // index[40] ASCON_BLOCK_CTRL_SHADOWED
    4'b 0001, // index[41] ASCON_TRIGGER
    4'b 0001, // index[42] ASCON_STATUS
    4'b 0001, // index[43] ASCON_OUTPUT_VALID
    4'b 1111, // index[44] ASCON_FSM_STATE
    4'b 0001, // index[45] ASCON_FSM_STATE_REGREN
    4'b 0001  // index[46] ASCON_ERROR
  };

endpackage