// TEST MODEL ONLY - written by ThreatShield because uart_tx.v was not supplied. NOT the Kavach uart_tx.
// Same ports as used in uart_to_reg_bridge.v; 8N1, LSB first. run_cosim.py uses the user's real uart_tx.v if present in KAVACH_RTL_DIR.
module uart_tx #(parameter CLKS_PER_BIT = 4)(input wire clk, input wire rst, input wire tx_start, input wire [7:0] data_in,
                                              output reg tx_out, output reg tx_busy);
    reg [3:0] cnt, bitn; reg [9:0] sh;
    always @(posedge clk or posedge rst) begin
        if (rst) begin tx_out <= 1; tx_busy <= 0; cnt <= 0; bitn <= 0; sh <= 10'h3FF; end
        else if (!tx_busy) begin
            if (tx_start) begin sh <= {1'b1, data_in, 1'b0}; tx_busy <= 1; cnt <= 0; bitn <= 0; tx_out <= 1'b0; end
        end else if (cnt == CLKS_PER_BIT - 1) begin
            cnt <= 0;
            if (bitn == 9) begin tx_busy <= 0; tx_out <= 1; end
            else begin bitn <= bitn + 1; tx_out <= sh[bitn + 1]; end
        end else cnt <= cnt + 1;
    end
endmodule
