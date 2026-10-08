import http from "http";
import assert from "assert";
import { app } from "./dist/app.js";

const server = http.createServer(app);

server.listen(0, "127.0.0.1", async () => {
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`[TEST] Test server running on ${baseUrl}`);

  try {
    // Test 1: Arbitrary file parameter should be rejected (400)
    console.log("[TEST 1] Testing /api/agent/download?file=etc/passwd rejection...");
    const resBad = await fetch(`${baseUrl}/api/agent/download?file=etc/passwd`);
    assert.strictEqual(resBad.status, 400, "Should reject arbitrary file query with 400");
    const jsonBad = await resBad.json();
    assert.strictEqual(jsonBad.error?.code, "INVALID_REQUEST");
    console.log("  ✅ Test 1 Passed: Arbitrary file queries blocked.");

    // Test 2: Valid approved download returns 200 and attachment header
    console.log("[TEST 2] Testing /api/agent/download...");
    const resGood = await fetch(`${baseUrl}/api/agent/download`);
    assert.strictEqual(resGood.status, 200, "Should return 200 OK for approved agent download");
    const contentDisp = resGood.headers.get("content-disposition");
    assert(contentDisp && contentDisp.includes('filename="PhantomTrace-Agent.exe"'), "Content-Disposition must specify PhantomTrace-Agent.exe");
    const arrayBuffer = await resGood.arrayBuffer();
    assert(arrayBuffer.byteLength > 1000000, `Downloaded binary must be valid size (got ${arrayBuffer.byteLength} bytes)`);
    console.log(`  ✅ Test 2 Passed: Downloaded ${arrayBuffer.byteLength} bytes of PhantomTrace-Agent.exe successfully.`);

    // Test 3: Installer download returns 200 and installer attachment header
    console.log("[TEST 3] Testing /api/agent/download?installer=true...");
    const resInstaller = await fetch(`${baseUrl}/api/agent/download?installer=true`);
    assert.strictEqual(resInstaller.status, 200, "Should return 200 OK for approved installer download");
    const contentDispInst = resInstaller.headers.get("content-disposition");
    assert(contentDispInst && contentDispInst.includes('filename="PhantomTrace_Agent_Setup.exe"'), "Content-Disposition must specify PhantomTrace_Agent_Setup.exe");
    const instArrayBuffer = await resInstaller.arrayBuffer();
    assert(instArrayBuffer.byteLength > 1000000, `Downloaded installer must be valid size (got ${instArrayBuffer.byteLength} bytes)`);
    console.log(`  ✅ Test 3 Passed: Downloaded ${instArrayBuffer.byteLength} bytes of PhantomTrace_Agent_Setup.exe successfully.`);

    console.log("[TEST SUCCESS] All download endpoint tests passed.");
    server.close(() => {
      process.exit(0);
    });
  } catch (err) {
    console.error("[TEST FAILED]", err);
    server.close(() => {
      process.exit(1);
    });
  }
});
