// PROPOSED interface (not derived from user's RTL). Receives the 7-byte frame over a byte stream
// (byte_valid/byte_data), checks CRC8 (poly 0x07), exposes result registers + status flags.
// Clock/reset: ASSUMED single clk, active-low synchronous rst_n. CONFIRM against target design.
module threat_result_if (
    input  wire        clk, rst_n,
    input  wire        byte_valid,
    input  wire [7:0]  byte_data,
    output reg         byte_ready,
    output reg  [3:0]  engine, risk,
    output reg  [7:0]  confidence, category, flags,
    output reg         result_valid,        // pulses 1 cycle on good frame
    output reg         err_crc, err_sync    // sticky until rst_n
);
    reg [2:0] idx; reg [7:0] b1,b2,b3,b4,b5; reg [7:0] crc;
    function [7:0] crc8_step(input [7:0] c, input [7:0] d);
        integer i; reg [7:0] x;
        begin x = c ^ d; for (i=0;i<8;i=i+1) x = x[7] ? ((x<<1) ^ 8'h07) : (x<<1); crc8_step = x; end
    endfunction
    always @(posedge clk) begin
        if (!rst_n) begin idx<=0; crc<=0; byte_ready<=1; result_valid<=0; err_crc<=0; err_sync<=0;
            engine<=0; risk<=0; confidence<=0; category<=0; flags<=0; end
        else begin
            result_valid <= 0;
            if (byte_valid && byte_ready) begin
                case (idx)
                  0: if (byte_data==8'hA5) idx<=1; else err_sync<=1;
                  1: begin b1<=byte_data; crc<=crc8_step(8'h00,byte_data); idx<=2; end
                  2: begin b2<=byte_data; crc<=crc8_step(crc,byte_data); idx<=3; end
                  3: begin b3<=byte_data; crc<=crc8_step(crc,byte_data); idx<=4; end
                  4: begin b4<=byte_data; crc<=crc8_step(crc,byte_data); idx<=5; end
                  5: begin b5<=byte_data; crc<=crc8_step(crc,byte_data); idx<=6; end
                  6: begin idx<=0;
                       if (crc==byte_data) begin engine<=b1[3:0]; risk<=b2[3:0]; confidence<=b3; category<=b4; flags<=b5; result_valid<=1; end
                       else err_crc<=1; end
                endcase
            end
        end
    end
endmodule
