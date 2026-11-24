`timescale 1ns/1ps
// Co-simulation: reads frames (hex) produced by Python (threatshield/hal/kavach.py), drives them into the USER's
// uart_to_reg_bridge + kavach_register_map, writes replies to rx_resp.txt. Register-map status inputs are tied to constants.
module tb_cosim;
    reg clk = 0, rst = 1; always #5 clk = ~clk;
    wire h2c, c2h; reg hs = 0; reg [7:0] hd = 0; wire hbusy;
    uart_tx #(.CLKS_PER_BIT(4)) HTX (.clk(clk), .rst(rst), .tx_start(hs), .data_in(hd), .tx_out(h2c), .tx_busy(hbusy));
    wire [7:0] rxb; wire rxv;
    uart_rx #(.CLKS_PER_BIT(4)) HRX (.clk(clk), .rst(rst), .rx_in(c2h), .data_out(rxb), .data_valid(rxv));
    wire rw, rr; wire [7:0] ra; wire [31:0] rwd, rrd; wire rrdy;
    uart_to_reg_bridge BR (.clk(clk), .rst(rst), .uart_rx_in(h2c), .uart_tx_out(c2h), .reg_write(rw), .reg_read(rr),
                           .reg_addr(ra), .reg_wdata(rwd), .reg_rdata(rrd), .reg_ready(rrdy));
    wire [31:0] challenge_o;
    kavach_register_map RM (.clk(clk), .rst(rst), .reg_write(rw), .reg_read(rr), .reg_addr(ra), .reg_wdata(rwd), .reg_rdata(rrd), .reg_ready(rrdy),
        .bist_pass_i(1'b1), .bist_fail_i(1'b0), .replay_detected_i(1'b1), .stable_response_i(32'hA5A5_0001), .unstable_bit_count_i(6'd7),
        .authentication_grant_i(1'b0), .auth_denied_bist_i(1'b0), .auth_denied_replay_i(1'b1),
        .sequence_violation_i(1'b1), .chain_complete_i(1'b0), .stages_completed_i(4'd3),
        .offline_budget_i(8'h5A), .sync_required_i(1'b1), .total_offline_uses_i(16'd9), .chain_hash_i(32'hC0FF_EE00),
        .key_locked_i(1'b0), .ciphertext_i(32'h0), .tx_counter_i(16'd0),
        .enroll_busy_i(1'b0), .mask_locked_i(1'b0), .reliability_mask_i(32'h0), .challenge_o(challenge_o));
    reg [31:0] resp = 0; integer nrx = 0;
    always @(posedge clk) if (rxv) begin resp <= {resp[23:0], rxb}; nrx <= nrx + 1; end
    task send_byte(input [7:0] b);
        begin wait (hbusy == 0); hd = b; hs = 1; @(posedge clk); #1; hs = 0; wait (hbusy == 1); wait (hbusy == 0); end
    endtask
    reg [47:0] frame; integer fd, fo, r, nresp, i, t;
    initial begin
        repeat (4) @(posedge clk); rst = 0; repeat (4) @(posedge clk);
        fd = $fopen("tx_frames.txt", "r"); fo = $fopen("rx_resp.txt", "w");
        while (!$feof(fd)) begin
            r = $fscanf(fd, "%h %d\n", frame, nresp);
            if (r == 2) begin
                nrx = 0;
                for (i = 0; i < 6; i = i + 1) send_byte(frame[47 - 8*i -: 8]);
                if (nresp > 0) begin
                    t = 0; while (nrx < nresp && t < 3000) begin @(posedge clk); t = t + 1; end
                    if (nrx < nresp) $fdisplay(fo, "TIMEOUT"); else $fdisplay(fo, "%08h", resp);
                end else begin repeat (60) @(posedge clk); $fdisplay(fo, "NORESP"); end
            end
        end
        $fdisplay(fo, "CHALLENGE_O=%08h", challenge_o); $fclose(fo); $finish;
    end
endmodule
