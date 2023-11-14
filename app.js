import dotenv from 'dotenv'
import express from 'express' 
import mongoose from 'mongoose'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import User from './models/User.js'

const app = express()
//configurar response para JSON
app.use(express.json())
dotenv.config()

mongoose.set('strictQuery', false)

//Middleware
const checkToken = (req, res, next)=>{
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(" ")[1]
    if(!token){
        res.status(401).json({msg: 'Acesso Negado'})
    }

    try {
        const secret = process.env.SECRET    
        jwt.verify( token, secret)
        next()

    } catch (error) {
        res.status(400).json({msg: 'Token inválido'})
    }

}


//Rota Private

app.get('/user/:id',checkToken,  async (req, res) =>{

    const id = req.params.id

    //verifica se o user existe no banco

    const user = await User.findById(id, '-password')

    if(!user){
        res.status(404).json({msg: 'Usuário não encontrado'})
    }

    res.status(200).json({user})

})



//Rota inicial e Publica
app.get('/', (req,res)=>{
    res.status(200).json({msg: "Bem vindo a nossa API"})
})

//Criar usuário
app.post('/auth/register', async (req, res)=>{
    const {name, email, password, confirmpassword} = req.body
    if (!name){
        return res.status(422).json({msg: 'O nome é obrigatório'})
    }
    if (!email){
        return res.status(422).json({msg: 'O e-mail é obrigatório'})
    }
    if (!password){
        return res.status(422).json({msg: 'A senha é obrigatório'})
    }
    if (password !== confirmpassword){
        return res.status(422).json({msg: 'Senhas diferentes'})
    }

    //Verificar se o usuário existe no banco
    const userExiste = await User.findOne({email:email})
    if (userExiste){
        return res.status(422).json({msg: 'O email já está cadastrado no banco'})
    }

    //criar senha
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //criar usuario
    const user = new User({
        name,
        email,
        password: passwordHash

    })    

    try {
        await user.save()
        res.status(201).json({msg: 'Usuário criado com sucesso'})
        
    } catch (error) {
        console.log(error)
        res.status(500).json({msg: 'Aconteceu um erro no servidor.'})
    }

})


//Login Usuário
app.post('/auth/login', async (req, res)=>{

    const {email, password} = req.body
    if (!email){
        return res.status(422).json({msg: 'O e-mail é obrigatório'})
    }
    if (!password){
        return res.status(422).json({msg: 'A senha é obrigatório'})
    }

    //Verificar se o usuário existe no banco
    const user = await User.findOne({email:email})
    if (!user){
        return res.status(404).json({msg: 'Usuário não encontrado'})
    }

    //Verifica a senha
    const checkPassword = await bcrypt.compare(password, user.password)
    if(!checkPassword){
        return res.status(422).json({msg: 'Senha inválida'})
    }

    //Autenticar com o SECRET
    try {

        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user.id
        },secret)

        res.status(200).json({msg:'Autenticação realizada com sucesso . ', token})
        
    } catch (error) {
        console.log(error)
        res.status(500).json({msg: 'Aconteceu um erro no servidor.'})
    }


})




mongoose.connect(`mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.2savc5r.mongodb.net/`)
    .then(()=>{
        app.listen(process.env.SERVER_PORT, ()=> console.log(`Servidor rodando na porta ${process.env.SERVER_PORT}`))
        console.log('Conectado no mongodb')
    })
    .catch((error)=> console.log(error))




