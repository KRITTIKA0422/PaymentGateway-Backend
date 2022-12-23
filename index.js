import express from "express";
import bcrypt from 'bcrypt';
import jwt from "jsonwebtoken";
import cors from "cors";
import bodyparser from "body-parser";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
dotenv.config();

const app=express();
app.use(cors())
app.use(bodyparser.urlencoded({extended:false}))
app.use(bodyparser.json())
const PORT=process.env.PORT || 4000
const MONGO_URL = process.env.MONGO_URL;
console.log(process.env.MONGO_URL);
async function createConnection() {
    const client = new MongoClient(MONGO_URL);
    await client.connect();
    console.log("Mongo is connected");
    return client;
}
const client = await createConnection();
app.get("/", function (request, response) {     //api endpoint for home page
    response.send("Welcome to Pizza App");
});

async function genHashedPassword(password){      //generating hashed password
    const NO_OF_ROUNDS=10;
    const salt=await bcrypt.genSalt(NO_OF_ROUNDS);
    const hashedPassword= await bcrypt.hash(password,salt);
    return hashedPassword;
}

app.post("/users/signup", async function (request, response) {     //users sign up and authorization
 const {username,password,isAdmin}=request.body;
 const userFromDB= await client.db("pizza-corner")
 .collection("users")
 .findOne({username: username});
 if(userFromDB){
    response.status(400).send({msg:"User already exists"});
 } else{
    const hashedPassword= await genHashedPassword(password);
    console.log(hashedPassword);
    const result= await client.db("pizza-corner")
    .collection("users")
    .insertOne({username: username, password:hashedPassword, isAdmin: isAdmin,});
    response.send(result);
 }
});
app.post("/users/login", async function (request, response) {       //checking for authentication and user login
    const {username,password}=request.body;
    const userFromDB= await client.db("pizza-corner")
    .collection("users")
    .findOne({username: username});
    if(!userFromDB){
       response.status(401).send({msg:"Invalid Credentials"});
    } else{
     const storePassword= userFromDB.password;
     const isPasswordMatch=await bcrypt.compare(password,storePassword);
     console.log(isPasswordMatch);

     if(isPasswordMatch){
        const token=jwt.sign({id:userFromDB._id},`${process.env.SECRET_KEY}`);
    await client.db("pizza-corner")
    .collection("session")
    .insertOne({username:userFromDB.username,userId: userFromDB._id, token:token,isAdmin:userFromDB.isAdmin,});
       
       response.send({msg:"Successful Login", token:token, isAdmin:userFromDB.isAdmin});
     } else{
        response.status(401).send({msg:"Invalid credentials"});
     }
    }
   });

app.post('/pizzas',async function (request, response){    //api for posting pizzas from pizza app
    const data = request.body;
    console.log(data);
    const result = await client.db("pizza-corner").collection("pizzas").insertOne(data);
    console.log(result);
    response.send(result);
});

app.get("/pizzas", async function (request, response) {            //api endpoint for getting pizzas
    console.log(request.query);
    const pizzas = await client.db("pizza-corner").collection("pizzas").find(request.query).toArray();
    response.send(pizzas);
});

app.delete("/pizzas/:id", async function (request, response) {            //api endpoint for deleting pizzas
const {id}=request.params;
console.log(request.params,id);
//check whether the user is admin
const token=request.header("x-auth-token");
console.log(token);
const userSession=await client.db("pizza-corner").collection("session").findOne({token:token});
if(userSession && userSession.isAdmin){
const result = await client.db("pizza-corner").collection("pizzas").deleteOne({_id:ObjectId(id)});
console.log(result); 
}else{
    response.status(401).send({msg:"Access Denied"});
}

});

app.listen(PORT,()=>{
    console.log(`App started in ${PORT}`);
})