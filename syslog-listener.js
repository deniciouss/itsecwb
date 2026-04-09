// Quick syslog listener for testing — listens on UDP 5140
const dgram = require("dgram");
const PORT = 5140;

const server = dgram.createSocket("udp4");

server.on("message", (msg, rinfo) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] from ${rinfo.address}:${rinfo.port}`);
  console.log(`  ${msg.toString()}`);
  console.log();
});

server.on("listening", () => {
  console.log(`Syslog listener running on UDP port ${PORT}`);
  console.log("Waiting for messages...\n");
});

server.bind(PORT);
