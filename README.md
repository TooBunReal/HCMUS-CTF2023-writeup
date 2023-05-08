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
