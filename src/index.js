import app from './app.js';
import dotenv from 'dotenv'
import connectDB from './db/db.js'


dotenv.config({ override: true });

const PORT = process.env.PORT || 3000;


connectDB()
.then(()=>{
    app.listen(PORT, ()=>{
    console.log(`server is running at http://localhost:${PORT}`)
})
})
.catch((err)=>{
    console.error("MogoDB connection error!", err);
    process.exit(1);
})

