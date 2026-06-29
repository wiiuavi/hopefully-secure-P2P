# hopefully-secure-P2P
This is my attempt at making a simple secure peer to peer client, using cryptographically secure key exchange.

# Key exchange
This program uses the Diffie Hellman key exchange, where both parties exchange a number 2^(random int) mod p, where p is a very large prime. Both then perform (key recieved)^(their random int) mod p, now holding the same private key, as any unwanted traffic won't know the random number. The program applies a bit-by-bit XOR mask to encrypt text, this also allows the same function to decrypt.

# Usage
upon running the program, you will see this screen:
<img width="602" height="476" alt="Screenshot 2026-06-29 214505" src="https://github.com/user-attachments/assets/ec4bedd7-8593-4eaa-9993-4f77746157ea" />
(Ip may differ)
once here, enter an internal network IP to connect to them and start talking! Or wait for them to do the same.
Run the program twice and use your own ip to test if it works, if you dont have another user!

# TODO
Will add accept/reject functionality, as well as braodcasting your IP. so you don't need to type it out manually. Will add functionality for files, and preview for common file types like mp3/mp4/png


