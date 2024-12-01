import express from 'express'
import userModel from '../models/userModel.js'
const router = express.Router();

router.get('/',async (req,res)=>{
    const result = await userModel.getAll();
    res.send(result)
})
router.post('/user',async (req,res)=>{
    let username = req.body.username
    let email = req.body.email
    let password = req.body.password
    let role = req.body.role

    const result = await userModel.addUser(username,password,email,role) 
    res.send(result)
})
router.post('/user/login',async(req,res)=>{
    let email = req.body.email
    let password = req.body.password
    let loggingSucces = false
    console.log(email)
    const result =  await userModel.logIn(email,password);
    if(result){
        loggingSucces=true
    }
    res.send(loggingSucces)
})
router.get('/checkLogin',async(req,res)=>{
    console.log(userModel.isLogged(req))
    res.send(200);
})
router.get('/count',async(req,res)=>{
    const result = await userModel.count();
    console.log(result)
    res.status(200).send({result})
})

export default router
