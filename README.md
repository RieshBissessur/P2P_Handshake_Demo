Public P2P Handshake Demo
=====================================================================================================================================================================
This is an example of a public Peer to Peer handshake demo using a Rust Console Application.

This project is dependant on RUST being installed

Rust can be installed by following these instructions:

	https://www.rust-lang.org/tools/install

Or on Mac OS X using this curl command:

	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh 

<br>

Running the Console Application
=====================================================================================================================================================================
- ## Compile and run the console application
  - In the project directory run the following commands to compile and run the console application.
 
  - ```  cargo run ```

  - This will run the main.rs fil which contrains a single handshake with the node at 13.247.54.166:8333.

<br>

- ## Unit Test


  - In the project directory run the following commands to compile and run the tests written for the console application.
 
  - ```  cargo test ```

  - The test performed attemptes to exchange versions with the nodes mentioned and then exchange verack messages if applicable as this is sometimes skipped. We say a handhsake with a node is successdessful if it sends either  a verack, sendcmpct or sendheaders message after sending the node our verack message.

  - The unit tests consist of doing a handhsake with three different nodes.
    - 13.247.54.166:8333 -  A full node hosted in Cape Town, South Africa 
    - 217.182.198.226:8333 - A full node hosted in Berlin, Germany
    - 136.49.63.216:8333 -  A full node hosted in Austin Texan, USA



<br>

