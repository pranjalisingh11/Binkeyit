import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name : {
        type : String,
        required : [true,"provide name"]
    },
    email : {
        type : String,
        required : [true, "provide email"],
        unique: true,
        match: [ // ✅ Validate email format using regex
            /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, 
            "Please enter a valid email"
        ]
    },
    password: {
        type : String,
        required : [true, "provide password"]
    },
    avatar : {
        type : String,
        default : ""
    },
    mobile : {
        type : Number,
        default : null
    },
    refresh_token : {
        type : String,
        default : ""
    },
    verify_email : {
        type : Boolean,
        default : false
    },
    last_login_date : {
        type : Date,
        default : ""
    },
    status : {
        type : String,
        enum : ["Active","Inactive","Suspended"],
        default : "Active"
    },
    forgot_password_otp : {
        type : String,
        default : null
    },
    forgot_password_expiry : {
        type : Date,
        default: () => new Date(Date.now() + 10 * 60 * 1000)
    },
    role : {
        type : String,
        enum : ['ADMIN',"USER"],
        default : "USER"
    },
},{
    timestamps : true
})

const UserModel = mongoose.model("User",userSchema)

export default UserModel