PSFree version 1.4.0

PSFree is a WebKit exploit using CVE-2022-22620 to gain arbitrary read/write.

vulnerable:
* PS4 6.xx-9.xx (tested 6.00-9.60)
* PS5 1.xx-5.xx (tested 1.00-5.50)

CREDITS:
* anonymous for PS4 firmware kernel dumps

* janisslsm from ps4-dev on discord.com
  * contributed ROP chain managers for 8.5x and 9.0x
  * contributer of the ROP chain manager for 9.5x
  * Helped in figuring out the size of JSC::ArrayBufferContents and its needed
    offsets on different firmwares.

* barooney from ps4-dev on discord.com
  * contributer of the ROP chain manager for 9.5x

* CelesteBlue from ps4-dev on discord.com
  * Helped in figuring out the size of WebCore::SerializedScriptValue and its
    needed offsets on different firmwares.
  * figured out the range of vulnerable firmwares

* Kameleon_ from ps4-dev discord
  * Asked people to test 1.3.0 (beta) on other firmwares and reported if the
    peformance boost worked (reports from 6.72-9.60).

* Quentin Meffre (@0xdagger) and Mehdi Talbi (@abu_y0ussef) for the 6.xx
  buildBubbleTree() UaF exploit that served as the framework for the exploit.

* Maddie Stone for the CVE writeup
