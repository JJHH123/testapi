require('dotenv').config()
const express = require('express');
const app = express();
const PORT = 5000 || process.env.PORT;
const cors = require('cors');
const mongoose = require('mongoose');
const User = require('./models/User');
const Post = require('./models/Post');
const asyncHandler = require('express-async-handler')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({dest:'uploads/'});
const fs = require('fs');

app.use(cors({credentials:true, origin:'http://localhost:3000'}));
app.use(express.json())
app.use(cookieParser())
const salt = bcrypt.genSaltSync(10)
const secret = process.env.JWT_SECRET
app.use('/uploads', express.static(__dirname + '/uploads'))
const uri = process.env.MONGO_URI

mongoose.connect(uri)
.then(() => console.log("connected"))
.catch(e => console.log(e))


app.get('/test', (req,res) => {
    res.json('ok')
})



app.post('/user/register', asyncHandler(async(req,res) => {
    const { username, password } = req.body;

    try{
        const newUser = await User.create({username,password: bcrypt.hashSync(password, salt)})
        res.json(newUser)
    } catch(e) {
        res.status(400).json(e);
    }
}))




app.post('/user/login', async(req,res) => {
    const { username, password } = req.body;
    const loginUser = await User.findOne({username});
    const passCheck = bcrypt.compareSync(password, loginUser.password)
    
    if(passCheck) {
        jwt.sign({ username, id:loginUser._id }, secret, {}, (err,token) => {
            if(err) {
                res.status(401).json('not authorized')
                throw err
            }
            res.cookie('token',token).json({
                id: loginUser._id,
                username: username,
                token:token
            })
        })
    } else {
        res.status(400).json('wrong credentials');
    }
})




app.get('/user/profile', asyncHandler(async(req,res) => {
    const { token } = req.cookies;
    if(token === undefined || token.length === 0) res.json('false')
    else {

        jwt.verify(token, secret, {}, (err,info) => {
            if(err) {
            console.log(err);
            res.status(401)
        }
            res.json(info)
        })
    }
}))


app.post('/user/logout', async(req,res) => {
    res.cookie('token','').json('ok')
})




// handle new post
app.post('/post/newpost', uploadMiddleware.single('file'), async(req,res) => {
    const { originalname, path } = req.file;
    const parts = originalname.split('.')
    const ext = parts[parts.length - 1].toLowerCase()
    const newPath = path+'.'+ext;
    fs.renameSync(path, path+'.'+ext)

    
    const { token } = req.cookies;
    jwt.verify(token, secret, {}, async(err,info) => {
        if(err) throw err;
        const { title, summary, content } = req.body;
        const newPostDoc = await Post.create({
            title,
            summary,
            content,
            cover: newPath,
            author: info.id,
        })
    })
    

    res.json('ok')
})




app.get('/allposts', async(req,res) => {
    const posts = await Post.find().populate('author', [ 'username' ])
    .sort({createdAt: -1})
    .limit(20)
    res.json(posts)
})




app.get('/post/:id', async(req,res) => {
    const {id} = req.params;
    const postData = await Post.findById(id).populate('author', ['username']);
    res.json(postData)
})



// update post
app.put('/post/update',uploadMiddleware.single('file'), async(req,res) => {
    let newPath = null;
    if (req.file) {
      const {originalname,path} = req.file;
      const parts = originalname.split('.');
      const ext = parts[parts.length - 1];
      newPath = path+'.'+ext;
      fs.renameSync(path, newPath);
    }
  
    const {token} = req.cookies;
    jwt.verify(token, secret, {}, async (err,info) => {
      if (err) throw err;
      const {id,title,summary,content} = req.body;
      const postDoc = await Post.findById(id);
      const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
      if (!isAuthor) {
        return res.status(400).json('not authorized');
      }
      await postDoc.updateOne({
        title,
        summary,
        content,
        cover: newPath ? newPath : postDoc.cover,
      });
  
      res.json(postDoc);
    });
  
    
})

app.listen(PORT, () => {
    console.log(`Listening at PORT ${PORT}`)
})