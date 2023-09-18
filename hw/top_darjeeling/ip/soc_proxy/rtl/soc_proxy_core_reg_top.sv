// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// Register Top module auto-generated by `reggen`

`include "prim_assert.sv"

module soc_proxy_core_reg_top (
  input clk_i,
  input rst_ni,
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,
  // To HW
  output soc_proxy_reg_pkg::soc_proxy_core_reg2hw_t reg2hw, // Write
  input  soc_proxy_reg_pkg::soc_proxy_core_hw2reg_t hw2reg, // Read

  // Integrity check errors
  output logic intg_err_o,

  // Config
  input devmode_i // If 1, explicit error return for unmapped register access
);

  import soc_proxy_reg_pkg::* ;

  localparam int AW = 4;
  localparam int DW = 32;
  localparam int DBW = DW/8;                    // Byte Width

  // register signals
  logic           reg_we;
  logic           reg_re;
  logic [AW-1:0]  reg_addr;
  logic [DW-1:0]  reg_wdata;
  logic [DBW-1:0] reg_be;
  logic [DW-1:0]  reg_rdata;
  logic           reg_error;

  logic          addrmiss, wr_err;

  logic [DW-1:0] reg_rdata_next;
  logic reg_busy;

  tlul_pkg::tl_h2d_t tl_reg_h2d;
  tlul_pkg::tl_d2h_t tl_reg_d2h;


  // incoming payload check
  logic intg_err;
  tlul_cmd_intg_chk u_chk (
    .tl_i(tl_i),
    .err_o(intg_err)
  );

  // also check for spurious write enables
  logic reg_we_err;
  logic [3:0] reg_we_check;
  prim_reg_we_check #(
    .OneHotWidth(4)
  ) u_prim_reg_we_check (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .oh_i  (reg_we_check),
    .en_i  (reg_we && !addrmiss),
    .err_o (reg_we_err)
  );

  logic err_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      err_q <= '0;
    end else if (intg_err || reg_we_err) begin
      err_q <= 1'b1;
    end
  end

  // integrity error output is permanent and should be used for alert generation
  // register errors are transactional
  assign intg_err_o = err_q | intg_err | reg_we_err;

  // outgoing integrity generation
  tlul_pkg::tl_d2h_t tl_o_pre;
  tlul_rsp_intg_gen #(
    .EnableRspIntgGen(1),
    .EnableDataIntgGen(1)
  ) u_rsp_intg_gen (
    .tl_i(tl_o_pre),
    .tl_o(tl_o)
  );

  assign tl_reg_h2d = tl_i;
  assign tl_o_pre   = tl_reg_d2h;

  tlul_adapter_reg #(
    .RegAw(AW),
    .RegDw(DW),
    .EnableDataIntgGen(0)
  ) u_reg_if (
    .clk_i  (clk_i),
    .rst_ni (rst_ni),

    .tl_i (tl_reg_h2d),
    .tl_o (tl_reg_d2h),

    .en_ifetch_i(prim_mubi_pkg::MuBi4False),
    .intg_error_o(),

    .we_o    (reg_we),
    .re_o    (reg_re),
    .addr_o  (reg_addr),
    .wdata_o (reg_wdata),
    .be_o    (reg_be),
    .busy_i  (reg_busy),
    .rdata_i (reg_rdata),
    .error_i (reg_error)
  );

  // cdc oversampling signals

  assign reg_rdata = reg_rdata_next ;
  assign reg_error = (devmode_i & addrmiss) | wr_err | intg_err;

  // Define SW related signals
  // Format: <reg>_<field>_{wd|we|qs}
  //        or <reg>_{wd|we|qs} if field == 1 or 0
  logic intr_state_we;
  logic [3:0] intr_state_qs;
  logic [3:0] intr_state_wd;
  logic intr_enable_we;
  logic [3:0] intr_enable_qs;
  logic [3:0] intr_enable_wd;
  logic intr_test_we;
  logic [3:0] intr_test_wd;
  logic alert_test_we;
  logic alert_test_fatal_alert_intg_wd;
  logic alert_test_fatal_alert_external_0_wd;
  logic alert_test_fatal_alert_external_1_wd;
  logic alert_test_fatal_alert_external_2_wd;
  logic alert_test_fatal_alert_external_3_wd;
  logic alert_test_recov_alert_external_0_wd;
  logic alert_test_recov_alert_external_1_wd;
  logic alert_test_recov_alert_external_2_wd;
  logic alert_test_recov_alert_external_3_wd;

  // Register instances
  // R[intr_state]: V(False)
  prim_subreg #(
    .DW      (4),
    .SwAccess(prim_subreg_pkg::SwAccessW1C),
    .RESVAL  (4'h0),
    .Mubi    (1'b0)
  ) u_intr_state (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (intr_state_we),
    .wd     (intr_state_wd),

    // from internal hardware
    .de     (hw2reg.intr_state.de),
    .d      (hw2reg.intr_state.d),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_state.q),
    .ds     (),

    // to register interface (read)
    .qs     (intr_state_qs)
  );


  // R[intr_enable]: V(False)
  prim_subreg #(
    .DW      (4),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (4'h0),
    .Mubi    (1'b0)
  ) u_intr_enable (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (intr_enable_we),
    .wd     (intr_enable_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_enable.q),
    .ds     (),

    // to register interface (read)
    .qs     (intr_enable_qs)
  );


  // R[intr_test]: V(True)
  logic intr_test_qe;
  logic [0:0] intr_test_flds_we;
  assign intr_test_qe = &intr_test_flds_we;
  prim_subreg_ext #(
    .DW    (4)
  ) u_intr_test (
    .re     (1'b0),
    .we     (intr_test_we),
    .wd     (intr_test_wd),
    .d      ('0),
    .qre    (),
    .qe     (intr_test_flds_we[0]),
    .q      (reg2hw.intr_test.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.intr_test.qe = intr_test_qe;


  // R[alert_test]: V(True)
  logic alert_test_qe;
  logic [8:0] alert_test_flds_we;
  assign alert_test_qe = &alert_test_flds_we;
  //   F[fatal_alert_intg]: 0:0
  prim_subreg_ext #(
    .DW    (1)
  ) u_alert_test_fatal_alert_intg (
    .re     (1'b0),
    .we     (alert_test_we),
    .wd     (alert_test_fatal_alert_intg_wd),
    .d      ('0),
    .qre    (),
    .qe     (alert_test_flds_we[0]),
    .q      (reg2hw.alert_test.fatal_alert_intg.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.alert_test.fatal_alert_intg.qe = alert_test_qe;

  //   F[fatal_alert_external_0]: 1:1
  prim_subreg_ext #(
    .DW    (1)
  ) u_alert_test_fatal_alert_external_0 (
    .re     (1'b0),
    .we     (alert_test_we),
    .wd     (alert_test_fatal_alert_external_0_wd),
    .d      ('0),
    .qre    (),
    .qe     (alert_test_flds_we[1]),
    .q      (reg2hw.alert_test.fatal_alert_external_0.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.alert_test.fatal_alert_external_0.qe = alert_test_qe;

  //   F[fatal_alert_external_1]: 2:2
  prim_subreg_ext #(
    .DW    (1)
  ) u_alert_test_fatal_alert_external_1 (
    .re     (1'b0),
    .we     (alert_test_we),
    .wd     (alert_test_fatal_alert_external_1_wd),
    .d      ('0),
    .qre    (),
    .qe     (alert_test_flds_we[2]),
    .q      (reg2hw.alert_test.fatal_alert_external_1.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.alert_test.fatal_alert_external_1.qe = alert_test_qe;

  //   F[fatal_alert_external_2]: 3:3
  prim_subreg_ext #(
    .DW    (1)
  ) u_alert_test_fatal_alert_external_2 (
    .re     (1'b0),
    .we     (alert_test_we),
    .wd     (alert_test_fatal_alert_external_2_wd),
    .d      ('0),
    .qre    (),
    .qe     (alert_test_flds_we[3]),
    .q      (reg2hw.alert_test.fatal_alert_external_2.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.alert_test.fatal_alert_external_2.qe = alert_test_qe;

  //   F[fatal_alert_external_3]: 4:4
  prim_subreg_ext #(
    .DW    (1)
  ) u_alert_test_fatal_alert_external_3 (
    .re     (1'b0),
    .we     (alert_test_we),
    .wd     (alert_test_fatal_alert_external_3_wd),
    .d      ('0),
    .qre    (),
    .qe     (alert_test_flds_we[4]),
    .q      (reg2hw.alert_test.fatal_alert_external_3.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.alert_test.fatal_alert_external_3.qe = alert_test_qe;

  //   F[recov_alert_external_0]: 5:5
  prim_subreg_ext #(
    .DW    (1)
  ) u_alert_test_recov_alert_external_0 (
    .re     (1'b0),
    .we     (alert_test_we),
    .wd     (alert_test_recov_alert_external_0_wd),
    .d      ('0),
    .qre    (),
    .qe     (alert_test_flds_we[5]),
    .q      (reg2hw.alert_test.recov_alert_external_0.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.alert_test.recov_alert_external_0.qe = alert_test_qe;

  //   F[recov_alert_external_1]: 6:6
  prim_subreg_ext #(
    .DW    (1)
  ) u_alert_test_recov_alert_external_1 (
    .re     (1'b0),
    .we     (alert_test_we),
    .wd     (alert_test_recov_alert_external_1_wd),
    .d      ('0),
    .qre    (),
    .qe     (alert_test_flds_we[6]),
    .q      (reg2hw.alert_test.recov_alert_external_1.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.alert_test.recov_alert_external_1.qe = alert_test_qe;

  //   F[recov_alert_external_2]: 7:7
  prim_subreg_ext #(
    .DW    (1)
  ) u_alert_test_recov_alert_external_2 (
    .re     (1'b0),
    .we     (alert_test_we),
    .wd     (alert_test_recov_alert_external_2_wd),
    .d      ('0),
    .qre    (),
    .qe     (alert_test_flds_we[7]),
    .q      (reg2hw.alert_test.recov_alert_external_2.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.alert_test.recov_alert_external_2.qe = alert_test_qe;

  //   F[recov_alert_external_3]: 8:8
  prim_subreg_ext #(
    .DW    (1)
  ) u_alert_test_recov_alert_external_3 (
    .re     (1'b0),
    .we     (alert_test_we),
    .wd     (alert_test_recov_alert_external_3_wd),
    .d      ('0),
    .qre    (),
    .qe     (alert_test_flds_we[8]),
    .q      (reg2hw.alert_test.recov_alert_external_3.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.alert_test.recov_alert_external_3.qe = alert_test_qe;



  logic [3:0] addr_hit;
  always_comb begin
    addr_hit = '0;
    addr_hit[0] = (reg_addr == SOC_PROXY_INTR_STATE_OFFSET);
    addr_hit[1] = (reg_addr == SOC_PROXY_INTR_ENABLE_OFFSET);
    addr_hit[2] = (reg_addr == SOC_PROXY_INTR_TEST_OFFSET);
    addr_hit[3] = (reg_addr == SOC_PROXY_ALERT_TEST_OFFSET);
  end

  assign addrmiss = (reg_re || reg_we) ? ~|addr_hit : 1'b0 ;

  // Check sub-word write is permitted
  always_comb begin
    wr_err = (reg_we &
              ((addr_hit[0] & (|(SOC_PROXY_CORE_PERMIT[0] & ~reg_be))) |
               (addr_hit[1] & (|(SOC_PROXY_CORE_PERMIT[1] & ~reg_be))) |
               (addr_hit[2] & (|(SOC_PROXY_CORE_PERMIT[2] & ~reg_be))) |
               (addr_hit[3] & (|(SOC_PROXY_CORE_PERMIT[3] & ~reg_be)))));
  end

  // Generate write-enables
  assign intr_state_we = addr_hit[0] & reg_we & !reg_error;

  assign intr_state_wd = reg_wdata[3:0];
  assign intr_enable_we = addr_hit[1] & reg_we & !reg_error;

  assign intr_enable_wd = reg_wdata[3:0];
  assign intr_test_we = addr_hit[2] & reg_we & !reg_error;

  assign intr_test_wd = reg_wdata[3:0];
  assign alert_test_we = addr_hit[3] & reg_we & !reg_error;

  assign alert_test_fatal_alert_intg_wd = reg_wdata[0];

  assign alert_test_fatal_alert_external_0_wd = reg_wdata[1];

  assign alert_test_fatal_alert_external_1_wd = reg_wdata[2];

  assign alert_test_fatal_alert_external_2_wd = reg_wdata[3];

  assign alert_test_fatal_alert_external_3_wd = reg_wdata[4];

  assign alert_test_recov_alert_external_0_wd = reg_wdata[5];

  assign alert_test_recov_alert_external_1_wd = reg_wdata[6];

  assign alert_test_recov_alert_external_2_wd = reg_wdata[7];

  assign alert_test_recov_alert_external_3_wd = reg_wdata[8];

  // Assign write-enables to checker logic vector.
  always_comb begin
    reg_we_check = '0;
    reg_we_check[0] = intr_state_we;
    reg_we_check[1] = intr_enable_we;
    reg_we_check[2] = intr_test_we;
    reg_we_check[3] = alert_test_we;
  end

  // Read data return
  always_comb begin
    reg_rdata_next = '0;
    unique case (1'b1)
      addr_hit[0]: begin
        reg_rdata_next[3:0] = intr_state_qs;
      end

      addr_hit[1]: begin
        reg_rdata_next[3:0] = intr_enable_qs;
      end

      addr_hit[2]: begin
        reg_rdata_next[3:0] = '0;
      end

      addr_hit[3]: begin
        reg_rdata_next[0] = '0;
        reg_rdata_next[1] = '0;
        reg_rdata_next[2] = '0;
        reg_rdata_next[3] = '0;
        reg_rdata_next[4] = '0;
        reg_rdata_next[5] = '0;
        reg_rdata_next[6] = '0;
        reg_rdata_next[7] = '0;
        reg_rdata_next[8] = '0;
      end

      default: begin
        reg_rdata_next = '1;
      end
    endcase
  end

  // shadow busy
  logic shadow_busy;
  assign shadow_busy = 1'b0;

  // register busy
  assign reg_busy = shadow_busy;

  // Unused signal tieoff

  // wdata / byte enable are not always fully used
  // add a blanket unused statement to handle lint waivers
  logic unused_wdata;
  logic unused_be;
  assign unused_wdata = ^reg_wdata;
  assign unused_be = ^reg_be;

  // Assertions for Register Interface
  `ASSERT_PULSE(wePulse, reg_we, clk_i, !rst_ni)
  `ASSERT_PULSE(rePulse, reg_re, clk_i, !rst_ni)

  `ASSERT(reAfterRv, $rose(reg_re || reg_we) |=> tl_o_pre.d_valid, clk_i, !rst_ni)

  `ASSERT(en2addrHit, (reg_we || reg_re) |-> $onehot0(addr_hit), clk_i, !rst_ni)

  // this is formulated as an assumption such that the FPV testbenches do disprove this
  // property by mistake
  //`ASSUME(reqParity, tl_reg_h2d.a_valid |-> tl_reg_h2d.a_user.chk_en == tlul_pkg::CheckDis)

endmodule