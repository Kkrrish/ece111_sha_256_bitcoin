module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);

// FSM state variables 
enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, WRITE} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic [31:0] w[16];
//logic [31:0] w_q[64];
logic [31:0] message[20];				// used to read the whole inpujt of 640bits from memory.

logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] a, b, c, d, e, f, g, h;
logic [7:0] i, j;
logic [15:0] offset; // in word address
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
//logic [512:0] memory_block;
//logic [7:0] tstep;
logic [1:0] blocks_left;
//logic [31:0] s0, s1;
logic 		cycle_block;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


//assign num_blocks = 2;
//assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
//assign tstep = (i - 1);

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
// Function to determine number of blocks in memory to fetch
/*
function logic [15:0] determine_num_blocks(input logic [31:0] size);

	// not needed
  // Student to add function implementati
endfunction
*/

// Word expansion function, to be used to generate w[16] onwards
function logic [31:0] wtnew;
	logic [31:0] s0, s1;
	
	s0 = rightrotate(w[1],7) ^ rightrotate(w[1],18) ^ (w[1]>>3);
	s1 = rightrotate(w[14],17) ^ rightrotate(w[14],19)  ^ (w[14]>>10);
	wtnew = w[0] + s0 + w[9] + s1;
	
endfunction


// SHA256 hash round
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

// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin

  if (!reset_n) begin
    cur_we 		<= 1'b0;
    state 		<= IDLE;
	offset 		<= 16'd0;
	a			<= 32'h0;
	b			<= 32'h0;
	c			<= 32'h0;
	d			<= 32'h0;
	e			<= 32'h0;
	f			<= 32'h0;
	g			<= 32'h0;
	h		 	<= 32'h0;		
	h0			<= 32'h0;
	h1			<= 32'h0;
	h2			<= 32'h0;
	h3			<= 32'h0;
	h4			<= 32'h0;
	h5			<= 32'h0;
	h6			<= 32'h0;
	h7			<= 32'h0;

		
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin
//		cur_we		<= 1'b0;				// for read cur_we = 0;
		i			<= 'd0;
		j			<= 'd0;
		blocks_left <= 2'd2;
		cycle_block <= 1'b0;
			

       if(start) begin
       // Student to add rest of the code  
			h0 <= 32'h6a09e667;
			h1 <= 32'hbb67ae85;
			h2 <= 32'h3c6ef372;
			h3 <= 32'ha54ff53a;
			h4 <= 32'h510e527f;
			h5 <= 32'h9b05688c;
			h6 <= 32'h1f83d9ab;
			h7 <= 32'h5be0cd19;

			offset 		<= 16'd1;
			cur_addr 	<= message_addr;
			state 		<= READ;
       end
	   else begin
	
			offset		<= 16'd0;
			cur_addr 	<= 'b0;
			state 		<= IDLE;
	   end
    end

 
	
	READ:	begin
				message[offset-1] <= mem_read_data; 
				if(offset == 20) begin
					state <= BLOCK;
					offset <= 'd0;
				end
				else begin	
					state 	<= READ;
					offset 	<= offset + 1;

				end

			end
			
	// SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory
    BLOCK: begin
	// Fetch message in 512-bit block size
	// For each of 512-bit block initiate hash value computation
		{a,b,c,d,e,f,g,h} <= {h0,h1,h2,h3,h4,h5,h6,h7};
		state <= COMPUTE;
		
		if(blocks_left==2) begin
			for(int t=0; t<16; t++) begin
				w[t] <= message[t];
			end;
	
		end
		else begin
				w[0] <= message[16];	
				w[1] <= message[17]; 
				w[2] <= message[18];
				w[3] <= message[19];
				w[4] <= 32'h80000000;
				for(int k=5; k<=14; k++) begin
					w[k] <= 32'd0;
				end
				w[15] <= 32'd640;
		end
	
    end

    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
    COMPUTE: begin
	// 64 processing rounds steps for 512-bit block 
		if(i==63) begin
			blocks_left <= blocks_left - 1;
		end
		
		if(i>=15) begin			// Now that all precomputed w[i]'s have been used, start generating
			w[15] <= wtnew();	// Next w[i] is produced one cycle before.
			for(int n=0; n<15; n++) begin
				w[n] <= w[n+1];	
			end
		end
		
        if (i < 64) begin
			if(i<=15)
				{a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h,w[i],i);
			else
				{a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h,w[15],i);	
				
			i <= i + 7'd1;
			state <= COMPUTE;
        end
		else begin
			{h0,h1,h2,h3,h4,h5,h6,h7} <= {h0+a,h1+b,h2+c,h3+d,h4+e,h5+f,h6+g,h7+h};	
			{a,b,c,d,e,f,g,h} <= {h0,h1,h2,h3,h4,h5,h6,h7};	// Redundant op, just to avoid latching
			i <= 'd0;
			if(blocks_left==0) begin
				state <= WRITE;
			end else
				state <= BLOCK;
		end

    end

    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
    WRITE: begin
		
		offset			<= offset+1;
		cur_we 			<= 1'b1;
		cur_addr 		<= output_addr - 1;
		case(offset)
			4'd0:	cur_write_data <= h0;
			4'd1:	cur_write_data <= h1;
			4'd2:	cur_write_data <= h2;
			4'd3:	cur_write_data <= h3;
			4'd4:	cur_write_data <= h4;
			4'd5:	cur_write_data <= h5;
			4'd6:	cur_write_data <= h6;
			4'd7:	cur_write_data <= h7;
			
		default:	cur_write_data <= 'h0;
		endcase
		
		if(offset==8)
			state <= IDLE;
		else
			state <= WRITE;
    end
	
   endcase
  end

// Generate done when SHA256 hash computation has finished and moved to IDLE state


always_comb begin

// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
	mem_clk = clk;
	mem_addr = cur_addr + offset;
	mem_we = cur_we;
	mem_write_data = cur_write_data;

	done = (state == IDLE);
	
end



endmodule
