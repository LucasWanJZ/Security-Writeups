## Challenge 
We are given a `.pcapng` file containing **214 packets**. The hint suggested it was related to **Havoc C2**, and that its GitHub repo would be useful.

## Approach 
### Step 1 : Recon 
**Wireshark Analysis**

![[ctf1.png]]


Opening the file in Wireshark revealed regular HTTP traffic. Key observations:
1. Every 2 seconds, the client `192.168.124.207` sends an `HTTP POST` request to the server `192.168.124.88` 
2. Every `HTTP POST` body has `deadbeef` in it 
3.  Most of the packets are short, but some are larger -> likely carrying useful data
4. The payloads are just gibberish -> definitely encrypted 🔐

**GitHub Research**
So, I pulled up the Havoc's GitHub to figure out how this things work. Maybe it could explain my observation above. I noted the following important points :
- Havoc runs with an **agent (demon)** and a **team server** exchanging encrypted packets periodically. (2 seconds)
- `OK` contains command from **team server** and `POST` usually contains the result after executing the commands
-  uses AES encryption to encrypt payload (CTR mode)
- `deadbeef` is a magic byte value. It acts as a marker for Havoc's C2 communication 
- I found the comment below in the source code, explaining the package's header structure :

``` C
  /*
     *  Header:
     *  [ SIZE         ] 4 bytes
     *  [ Magic Value  ] 4 bytes
     *  [ Agent ID     ] 4 bytes
     *  [ COMMAND ID   ] 4 bytes
     *  [ Request ID   ] 4 bytes
    */
```

So now I had a plan :
1. Extract AES key + IV 
2. Decrypt suspicious packets 
3. Hope the flag appears

### Step 2 : Capturing the flag 
**Finding key and IV**
From `Demon.c` :

``` C
/* 
* Header (if specified): 
  [ SIZE ] 4 bytes 
  [ Magic Value ] 4 bytes 
  [ Agent ID ] 4 bytes 
  [ COMMAND ID ] 4 bytes 
  [ Request ID ] 4 bytes 
  
  MetaData: 
  [ AES KEY ] 32 bytes 
  [ AES IV ] 16 bytes ... 
```

This snippet shows how Demon builds the meta data package that gets sent during initialization. I parsed the value of the first `HTTP POST` packet : 

```
# Header
- 00000117 (size)
- deadbeef (magic value) 
- 7b5387d4 (agent ID)
- 00000063 (command ID)
- 00000000 (request ID)

# Metadata
- 3aa2a0ee9a940c903a44a6c6b80af0e0be8a8ada445e1ec46a78a6ca326a0664 (AES Key 32 bytes)
- cc3e4494b88ed082c4e49ce43eec5aba (IV 16 bytes)
```

I tried decrypting a large packet with those values :

```
Z¼M/nj Volume in drive C has no label.
 Volume Serial Number is D078-8C18

 Directory of C:\Users\user\Downloads

11/01/2025  14:50    <DIR>          .
11/01/2025  14:50    <DIR>          ..
01/12/2024  09:19               940 cacert.der
06/01/2025  18:56            96,768 demon.x64.exe
06/01/2025  19:03            99,328 demon_http.x64.exe
11/01/2025  14:57                38 flag.txt              <- flag is probably in here
07/11/2024  21:11        52,895,736 SysinternalsSuite.zip
06/01/2025  19:02            99,328 Unconfirmed 339793.crdownload
               6 File(s)     53,192,138 bytes
               2 Dir(s)  33,796,202,496 bytes free
¼M/
```

I'll be honest: I wasted an hour at first because i forgot to strip the header before decrypting. But I found the key and IV :) 

**Decrypting the packets**
With the correct key and IV in hand, decrypting the encrypted payloads became straightforward, except for one problem: I didn’t know how many bytes to strip off as the header in the `OK` packets. Without the right cutoff, the decrypted output was just nonsense. After poking around, I noticed that whenever the team server sent no commands, those packets were always 12 bytes long. Stripping them out finally gave me clean decrypted data :

```
8c:\windows\system32\cmd.exe/c "C:\Program Files\7-Zip\7z.exe" a -pN3v3rG0nn4G1v3uUp flag.zip flag.txt
```

This command runs **`cmd.exe`** to invoke **7-Zip** and create a password-protected archive (`flag.zip`) containing `flag.txt`, using the password **`N3v3rG0nn4G1v3uUp`**. 

**Capture the Flag**
I was stuck here for a while, until I realized that ZIP archives have clear file signatures: they always start with the bytes `50 4B 03 04` and end with the bytes `50 4B 05 06`.

In the traffic, I spotted a server command instructing the agent to send `flag.zip`. By examining the decrypted response from the agent, I copied the exact byte range between these ZIP markers and saved it locally as `flag.zip`. With the archive reconstructed, I supplied the password, extracted its contents, and finally retrieved the flag 🚩

Final Flag: [CSCG{N3v3r_g0nn4_l3t_you_d0wn_3919583}](https://www.youtube.com/watch?v=XfELJU1mRMg)





