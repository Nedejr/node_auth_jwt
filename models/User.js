import mongoose from 'mongoose'

const User = mongoose.model('User',{
    name: String, 
    email: String, 
    password: String, 
    confirmpassword: String


})


export default User