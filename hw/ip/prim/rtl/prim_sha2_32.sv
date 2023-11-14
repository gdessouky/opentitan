// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// 32-bit input wrapper for the SHA-2 engine

module prim_sha2_32 import prim_sha2_pkg::*;
#(
  parameter bit MultimodeEn = 0 // assert to enable multi-mode feature
 ) (
  input clk_i,
  input rst_ni,

  input              wipe_secret,
  input sha_word32_t wipe_v,

  // Control signals and message words input to the message FIFO
  input               fifo_rvalid,      // indicates that there are data words/word parts
                                        // fifo_rdata ready to write into the SHA-2 padding buffer
  input  sha_fifo32_t fifo_rdata,
  output logic        fifo_rready, // indicates that the wrapper word accumulation buffer is
                                         // ready to receive words to feed into the SHA-2 engine

  // Control signals
  input                sha_en, // if disabled, it clears internal content
  input                hash_start,
  input digest_mode_e  digest_mode,
  input                hash_process,
  output logic         hash_done,

  input [127:0]             message_length, // use extended message length 128 bits
  output sha_word64_t [7:0] digest,         // use extended digest length
  output logic              idle
);

  sha_fifo64_t  word_buffer_d, word_buffer_q;
  sha_fifo64_t  full_word;
  logic [1:0]   word_part_count_d, word_part_count;
  logic         word_part_inc, word_part_reset;
  logic         sha_process, process_flag, process_flag_d;
  logic         word_valid, sha_ready;
  digest_mode_e digest_mode_flag, digest_mode_flag_d;

  always_comb begin : accumulate_word
    if (MultimodeEn) begin
      word_part_inc                 = 1'b0;
      word_part_reset               = 1'b0;
      full_word.mask                = 8'hFF; // to keep the padding buffer ready to receive
      full_word.data                = 64'h0;
      sha_process                   = 1'b0;
      word_valid                    = 1'b0;
      fifo_rready                   = 1'b0;
      word_buffer_d                 = word_buffer_q;

      if (sha_en && fifo_rvalid) begin // valid incoming word part and SHA engine is enabled
        if (word_part_count == 2'b00) begin
          if (digest_mode_flag != SHA2_256) begin
            // accumulate most significant 32 bits of word and mask bits
            word_buffer_d.data[63:32] = fifo_rdata.data;
            word_buffer_d.mask[7:4]   = fifo_rdata.mask;
            word_part_inc             =  1'b1;
            fifo_rready               = 1'b1;
            if (hash_process || process_flag) begin // ready to push out word (partial)
              word_valid      = 1'b1;
              // add least significant padding
              full_word.data  =  {fifo_rdata.data, 32'b0};
              full_word.mask  =  {fifo_rdata.mask, 4'h0};
              sha_process     = 1'b1;
              if (sha_ready == 1'b1) begin
                // if word has been absorbed into hash engine
                fifo_rready = 1'b1; // word pushed out to SHA engine, word buffer ready
                word_part_inc     = 1'b0;
              end else begin
                fifo_rready = 1'b0;
              end
            end
          end else begin   // SHA2_256 so pad and push out the word
            word_valid = 1'b1;
            // store the word with most significant padding
            word_buffer_d.data = {32'b0, fifo_rdata.data};
            word_buffer_d.mask = {4'hF, fifo_rdata.mask}; // pad with all-1 byte mask

            // pad with all-zero data and all-one byte masking and push word out already for 256
            full_word.data =  {32'b0, fifo_rdata.data};
            full_word.mask = {4'hF, fifo_rdata.mask};
            if (hash_process || process_flag) begin
                sha_process = 1'b1;
            end
            if (sha_ready == 1'b1) begin
              // if word has been absorbed into hash engine
              fifo_rready = 1'b1; // word pushed out to SHA engine so word buffer ready
            end else begin
              fifo_rready = 1'b0;
            end
          end
        end else if (word_part_count == 2'b01) begin
          fifo_rready = 1'b1; // buffer still has room for another word
          // accumulate least significant 32 bits and mask
          word_buffer_d.data [31:0] = fifo_rdata.data;
          word_buffer_d.mask [3:0]  = fifo_rdata.mask;

          // now ready to pass full word through
          word_valid              = 1'b1;
          full_word.data [63:32]  = word_buffer_q.data[63:32];
          full_word.mask [7:4]    = word_buffer_q.mask[7:4];
          full_word.data [31:0]   = fifo_rdata.data;
          full_word.mask  [3:0]   = fifo_rdata.mask;

          if (hash_process || process_flag) begin
              sha_process = 1'b1;
          end
          if (sha_ready == 1'b1) begin
            // word has been consumed
            fifo_rready       = 1'b1; // word pushed out to SHA engine so word buffer ready
            word_part_reset   = 1'b1;
            word_part_inc     = 1'b0;
          end else begin
            fifo_rready       = 1'b1;
            word_part_inc     = 1'b1;
          end
        end else if (word_part_count == 2'b10) begin // word buffer is full and not loaded out yet
          // fifo_rready is now deasserted: accumulated word is waiting to be pushed out
          fifo_rready        = 1'b0;
          word_valid        = 1'b1; // word buffer is ready to shift word out to SHA engine
          full_word         = word_buffer_q;
          if (hash_process || process_flag) begin
              sha_process   = 1'b1;
          end
          if (sha_ready == 1'b1) begin // waiting on sha_ready to turn 1
            // do not assert fifo_rready yet
            word_part_reset = 1'b1;
          end
        end
      end else if (sha_en) begin // hash engine still enabled but no new valid input
        // provide the last latched input so long as hash is enabled
        full_word = word_buffer_q;
        if (word_part_count == 2'b00 && (hash_process || process_flag)) begin
          sha_process = 1'b1; // wait on hash_process
        end else if (word_part_count == 2'b01 && (hash_process || process_flag)) begin
          // 384/512: msg ended: apply 32-bit word packing and push last word
          full_word.data [31:0] = 32'b0;
          full_word.mask [3:0]  = 4'h0;
          word_valid            = 1'b1;
          sha_process           = 1'b1;
          if (sha_ready == 1'b1) begin // word has been consumed
            word_part_reset = 1'b1; // which will also reset word_valid in the next cycle
          end
        end else if (word_part_count == 2'b01) begin // word feeding stalled but msg not ended
          word_valid = 1'b0;
        end else if (word_part_count == 2'b10 && (hash_process || process_flag)) begin
          // 384/512: msg ended but last word still waiting to be fed in
          word_valid  = 1'b1;
          sha_process = 1'b1;
          if (sha_ready == 1'b1) begin // word has been consumed
            word_part_reset = 1'b1; // which will also reset word_valid in the next cycle
          end
        end else if (word_part_count == 2'b10) begin // word feeding stalled
          word_valid = 1'b0;
        end
      end
    end else begin   // MultimodeEn = 0
      full_word.data = {32'b0, fifo_rdata.data};
      full_word.mask = {4'hF,  fifo_rdata.mask};
    end
  end

  generate
    if (MultimodeEn) begin  : gen_sha2_multi
      // Instantiate 64-bit SHA-2 multi-mode
      prim_sha2 #(
          .MultimodeEn(1)
      ) u_prim_sha2_multimode (
        .clk_i (clk_i),
        .rst_ni (rst_ni),
        .wipe_secret      (wipe_secret),
        .wipe_v           ({wipe_v, wipe_v}),
        .fifo_rvalid      (word_valid),
        .fifo_rdata       (full_word),
        .fifo_rready      (sha_ready),
        .sha_en           (sha_en),
        .hash_start       (hash_start),
        .digest_mode      (digest_mode),
        .hash_process     (sha_process),
        .hash_done        (hash_done),
        .message_length   (message_length),
        .digest           (digest),
        .idle             (idle)
      );
    end else begin  : gen_sha2_256
      prim_sha2 #(
          .MultimodeEn(0)
      ) u_prim_sha2_256 (
        .clk_i (clk_i),
        .rst_ni (rst_ni),
        .wipe_secret      (wipe_secret),
        .wipe_v           ({wipe_v, wipe_v}),
        .fifo_rvalid      (fifo_rvalid), // feed input directly
        .fifo_rdata       (full_word),
        .fifo_rready      (fifo_rready),
        .sha_en           (sha_en),
        .hash_start       (hash_start),
        .digest_mode      (),             // unconnected
        .hash_process     (hash_process), // feed input port directly to SHA-2 engine
        .hash_done        (hash_done),
        .message_length   ({{64'b0}, message_length[63:0]}),
        .digest           (digest),
        .idle             (idle)
      );
    end
  endgenerate

  always_comb begin
    if (MultimodeEn) begin
      // assign word_part_count_d
      if ((word_part_reset || hash_start || !sha_en)) word_part_count_d = '0;
      else if (word_part_inc)                         word_part_count_d = word_part_count + 1'b1;
      else                                            word_part_count_d = word_part_count;

      // assign digest_mode_flag_d
      if (hash_start)     digest_mode_flag_d = digest_mode;       // latch in configured mode
      else if (hash_done) digest_mode_flag_d = None;              // clear
      else                digest_mode_flag_d = digest_mode_flag;  // keep

      // assign process_flag
      if (!sha_en || hash_start) process_flag_d = 1'b0;
      else if (hash_process)     process_flag_d = 1'b1;
      else                       process_flag_d = process_flag;

      // assign word_buffer
      if (!sha_en || hash_start) word_buffer_d = 0;
      else                       word_buffer_d = word_buffer_q;
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)          word_part_count <= '0;
    else if (MultimodeEn) word_part_count <= word_part_count_d;
  end


  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)          word_buffer_q <= 0;
    else if (MultimodeEn) word_buffer_q <= word_buffer_d;
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)          process_flag <= '0;
    else if (MultimodeEn) process_flag <= process_flag_d;
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)          digest_mode_flag <= None;
    else if (MultimodeEn) digest_mode_flag <= digest_mode_flag_d;
  end
endmodule : prim_sha2_32
