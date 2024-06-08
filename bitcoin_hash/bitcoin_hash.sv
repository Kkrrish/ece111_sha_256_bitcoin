module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter NUM_NONCES = 16;

enum logic [4:0] {IDLE, READ, BLOCK, PHASE1, BLOCK2, PHASE2, BLOCK3, PHASE3, WRITE} state;

logic [31:0]		message[19];
logic [15:0]		cur_addr;
logic 				cur_we;
logic [6:0]		offset;
logic [31:0]		cur_write_data;

logic [31:0]		h0_og, h1_og, h2_og, h3_og, h4_og, h5_og, h6_og, h7_og;
logic [31:0]		w[NUM_NONCES][16];
logic [6:0]			i;
// SHA Hash Accumulation across 64 iterations for all Phases happens in these a-h variables
// For Phase 1: We will only use a[0], b[0] etc
// For Phase 2: Each nonce will use a[nonce], b[nonce] etc
logic [31:0]		a[NUM_NONCES], b[NUM_NONCES], c[NUM_NONCES], d[NUM_NONCES], e[NUM_NONCES], f[NUM_NONCES], g[NUM_NONCES], h[NUM_NONCES];
	

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

//Function declarations
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction

function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;

    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

function logic [31:0] wtnew2(input logic [4:0] x);
	logic [31:0] s0, s1;
	
	s0 = rightrotate(w[x][1],7) ^ rightrotate(w[x][1],18) ^ (w[x][1]>>3);
	s1 = rightrotate(w[x][14],17) ^ rightrotate(w[x][14],19)  ^ (w[x][14]>>10);
	wtnew2 = w[x][0] + s0 + w[x][9] + s1;
	
endfunction




//****************************************************************
always_ff @(posedge clk, negedge reset_n) begin

	
	if(!reset_n) begin
		state		<= IDLE;
		cur_we		<= 1'b0;
		offset		<= 16'd0;
		i 			<= 'd0;
		
	end


	else case(state)

		IDLE:	begin
			if(start) begin
				state 		<= READ;
				offset 		<= 16'd1;
				cur_addr	<= message_addr;
				h0_og 			<= 32'h6a09e667;
				h1_og 			<= 32'hbb67ae85;
				h2_og 			<= 32'h3c6ef372;
				h3_og 			<= 32'ha54ff53a;
				h4_og 			<= 32'h510e527f;
				h5_og 			<= 32'h9b05688c;
				h6_og 			<= 32'h1f83d9ab;
				h7_og 			<= 32'h5be0cd19;
				a[0] 				<= 32'h6a09e667;
				b[0]	 			<= 32'hbb67ae85;
				c[0]	 			<= 32'h3c6ef372;
				d[0]				<= 32'ha54ff53a;
				e[0]	 			<= 32'h510e527f;
				f[0]	 			<= 32'h9b05688c;
				g[0]	 			<= 32'h1f83d9ab;
				h[0]	 			<= 32'h5be0cd19;				
			end
			else begin
				state 		<= IDLE;
				offset 		<= 16'd0;
				cur_addr	<= 16'd0;
			end
		end // IDLE
		
		READ:	begin		
			message[offset-1]	<= mem_read_data;

			if(offset == 19) begin
				state 	<= BLOCK;
				offset	<= 'd0;
			end
			else begin
				state 	<= READ;
				offset	<= offset + 1;
			end		
		end // READ
		
		BLOCK:	begin
			for(logic[5:0] t=0; t<16; t++) begin
					w[0][t] <= message[t];
			end;
		
			state <= PHASE1;
		end // BLOCK
			
		PHASE1:	begin	
			w[0][15] <= wtnew2(0);	// Next w[i] is produced ~15 cycles beforehand
			for(logic[5:0] n=0; n<15; n++) begin
				w[0][n] <= w[0][n+1];	
			end
		
			if (i < 64) begin
				{a[0],b[0],c[0],d[0],e[0],f[0],g[0],h[0]} <= sha256_op(a[0],b[0],c[0],d[0],e[0],f[0],g[0],h[0],w[0][0],i);	
				i <= i + 7'd1;
				state <= PHASE1;		
			end
			else begin	
				{h0_og, h1_og, h2_og, h3_og, h4_og, h5_og, h6_og, h7_og} <= {a[0]+h0_og, b[0]+h1_og, c[0]+h2_og, d[0]+h3_og, e[0]+h4_og, f[0]+h5_og, g[0]+h6_og, h[0]+h7_og};	
				i <= 'd0;
				state <=BLOCK2;
			end			
		end // PHASE1
	
		BLOCK2:	begin
			for(logic[5:0] t=0; t<16; t++) begin
				for(logic[5:0] x=0; x<NUM_NONCES; x++) begin
					if(t<3) w[x][t] <= message[t+16];
					else if(t==3) w[x][t] <= x;
					else if(t==4) w[x][t] <= 32'h80000000;
					else if(t==15) w[x][t] <= 32'd640;
					else w[x][t] <= 0;
				end
			end;		
		
			for(logic[5:0] x=0; x<NUM_NONCES; x++) begin
				{a[x],b[x],c[x],d[x],e[x],f[x],g[x],h[x]} <= {h0_og, h1_og, h2_og, h3_og, h4_og, h5_og, h6_og, h7_og};
			end
	
			state <= PHASE2;
		end // BLOCK2
	
	
		PHASE2:	begin
			for(logic [4:0] x=0; x<NUM_NONCES; x++) begin
				w[x][15] <= wtnew2(x);	// Next w[i] is produced ~15 cycles beforehand
				for(int n=0; n<15; n++) begin
					w[x][n] <= w[x][n+1];	
				end
				
				if (i < 64) begin
					{a[x],b[x],c[x],d[x],e[x],f[x],g[x],h[x]} <= sha256_op(a[x],b[x],c[x],d[x],e[x],f[x],g[x],h[x], w[x][0], i);
					i <= i + 7'd1;
					state <= PHASE2;
				end
				else begin
					{a[x],b[x],c[x],d[x],e[x],f[x],g[x],h[x]}	<= {a[x]+h0_og,b[x]+h1_og,c[x]+h2_og,d[x]+h3_og,e[x]+h4_og,f[x]+h5_og,g[x]+h6_og,h[x]+h7_og}; 
					h0_og 			<= 32'h6a09e667;
					h1_og 			<= 32'hbb67ae85;
					h2_og 			<= 32'h3c6ef372;
					h3_og 			<= 32'ha54ff53a;
					h4_og 			<= 32'h510e527f;
					h5_og 			<= 32'h9b05688c;
					h6_og 			<= 32'h1f83d9ab;
					h7_og 			<= 32'h5be0cd19;
					i <= 'd0;
					state <= BLOCK3;
				end
			end // for NUM_NONCES
		end // PHASE2
	
		BLOCK3:	begin
			for(logic[5:0] x=0; x<NUM_NONCES; x++) begin			
				w[x][0] <= a[x];
				w[x][1] <= b[x];
				w[x][2] <= c[x];
				w[x][3] <= d[x];
				w[x][4] <= e[x];
				w[x][5] <= f[x];
				w[x][6] <= g[x];
				w[x][7] <= h[x];
				w[x][8]	<= 32'h80000000;
				for(logic[5:0] k=9; k<15; k++) begin
					w[x][k]	<= 32'd0;
				end
					w[x][15]	<= 32'd256;
					
				{a[x],b[x],c[x],d[x],e[x],f[x],g[x],h[x]} <= {h0_og, h1_og, h2_og, h3_og, h4_og, h5_og, h6_og, h7_og};
			end
			
			state <= PHASE3;
		end // BLOCK3
		
		PHASE3: begin
			for(logic [4:0] y=0; y<NUM_NONCES; y++) begin
				w[y][15] <= wtnew2(y);	// Next w[i] is produced ~15 cycles beforehand
				for(int n=0; n<15; n++) begin
					w[y][n] <= w[y][n+1];	
				end
				
				if (i < 64) begin
					{a[y],b[y],c[y],d[y],e[y],f[y],g[y],h[y]} <= sha256_op(a[y],b[y],c[y],d[y],e[y],f[y],g[y],h[y], w[y][0], i);
					i <= i + 7'd1;
					state <= PHASE3;
				end
				else begin
					{a[y],b[y],c[y],d[y],e[y],f[y],g[y],h[y]} <= {a[y]+h0_og,b[y]+h1_og,c[y]+h2_og,d[y]+h3_og,e[y]+h4_og,f[y]+h5_og,g[y]+h6_og,h[y]+h7_og};	// Redundant op, just to avoid latching
					i <= 'd0;
					state <= WRITE;
				end
			end // for NUM_NONCES
		end	// PHASE3
				
		WRITE: begin
			offset		<= offset+1;
			cur_we		<= 1'b1;
			cur_addr	<= output_addr - 1;
		
			cur_write_data <= a[offset];
		
			if(offset==16)
				state <= IDLE;
			else
				state <= WRITE;
			
		end // WRITE
	
	endcase;
end

always_comb begin

	mem_clk = clk;
	mem_addr = cur_addr + offset;
	mem_we = cur_we;
	mem_write_data = cur_write_data;

	done = (state == IDLE);
	

end


endmodule
