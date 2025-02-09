import sendEmail from '../config/sendEmail.js'
import UserModel from '../models/user.model.js'
import bcryptjs from 'bcryptjs'
import verifyEmailTemplate from '../utils/verifyEmailTemplate.js'
import generatedAccessToken from '../utils/generatedAccessToken.js'
import generatedRefreshToken from '../utils/genratedRefreshToken.js'
import uploadImageClodinary from '../utils/uploadImageClodinary.js'
import generatedOtp from '../utils/generatedOtp.js'
import forgotPasswordTemplate from '../utils/forgotPasswordTemplate.js'
import jwt from 'jsonwebtoken'

//register controller
export async function registerUserController(request,response) {
    try {
        const { name, email, password } = request.body

        if(!name || !email || !password){
            return response.status(400).json({
                message : "provide email, name, password",
                error : true,
                success : false
            })
        }

        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: "Invalid email format" });
        }

        const user = await UserModel.findOne({ email })

        if(user){
            return response.json({
                message : "Already registered email",
                error : true,
                success : false
            })
        }

        const salt = await bcryptjs.genSalt(10)
        const hashPassword = await bcryptjs.hash(password, salt)

        const payload = {
            name,
            email,
            password : hashPassword
        }

        const newUser = new UserModel(payload)
        const save = await newUser.save()

        const VerifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`

        const verifyEmail = await sendEmail({
            sendTo : email,
            subject : "Verify email from Binkeyit",
            html : verifyEmailTemplate({
                name,
                url : VerifyEmailUrl
            })
        })

        return response.json({
            message : "User register successfully",
            error : false,
            success : true,
            data : save
        })

    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

//verify email controller
export async function verifyEmailController(request,response){
    try {
        const { code } = request.body

        const user = await UserModel.findOne({ _id : code})

        if(!user){
            return response.status(400).json({
                message : "Invalid code",
                error : true,
                success : false
            })
        }

        const updateUser = await UserModel.updateOne({ _id : code },{
            verify_email : true
        })

        return response.json({
            message : "Verification done",
            success : true,
            error : false
        })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : true
        })
    }
}

//login controller
export async function loginController(request,response) {
    try {
        const {email, password} = request.body


        if(!email || !password){
            return response.status(400).json({
                message : "Provide email, password",
                error : true,
                success : false
            })
        }

        const user = await UserModel.findOne({ email })

        if(!user){
            return response.status(400).json({
                message : "User not registered",
                error : true,
                success: false
            })
        }

        if(user.status != "Active") {
            return response.status(400).json({
                message : "Contact to Admin",
                message : true,
                success : false
            })
        }

        const checkPassword = await bcryptjs.compare(password,user.password)

        if(!checkPassword){
            return response.status(400).json({
                message : "Check your password",
                error : true,
                success : false
            })
        }

        const accesstoken = await generatedAccessToken(user._id)
        const refreshToken = await generatedRefreshToken(user._id)

        const cookiesOption = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }
        response.cookie('accessToken',accesstoken,cookiesOption)
        response.cookie('refreshToken',refreshToken,cookiesOption)

        return response.json({
            message : "Login successfully",
            error : false,
            success : true,
            data : {
                accesstoken,
                refreshToken
            }
        })


    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

//logout controller
export async function logoutController(request,response) {
    try {
        const userid = request.userId
        const cookiesOption = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }
        response.clearCookie("accessToken",cookiesOption)
        response.clearCookie("refreshToken",cookiesOption)

        const removeRefreshToken = await UserModel.findByIdAndUpdate(userid, {
            refresh_token : ""
        })

        return response.json({
            message : "Logout successfully",
            error : false,
            success : true
        })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

//upload user avatar
export async function uploadAvatar(request,response) {
    try {
        const userId = request.userId //auth middleware
        const image = request.file //multer middleware

        const upload = await uploadImageClodinary(image)

        const updateUser = await UserModel.findByIdAndUpdate(userId, {
            avatar : upload.url
        })

        return response.json({
            message : "upload profile",
            data : {
                _id : userId,
                avatar : upload.url
            }
        })

    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

// update user details
export async function updateUserDetails(request,response) {
    try {
        const userId = request.userId
        const { name, email, mobile, password } = request.body

        let hashPassword = ""

        if(password){
            const salt = await bcryptjs.genSalt(10)
            hashPassword = await bcryptjs.hash(password, salt)
        }

        const updateUser = await UserModel.updateOne({ _id : userId }, {
            ...(name && { name : name }),
            ...(email && { email : email }),
            ...(mobile && { mobile : mobile }),
            ...(password && { password : hashPassword })
        })

        return response.json({
            message : "updated user successfully",
            error : false,
            success : true,
            data : updateUser
        })

    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

//forgot password not login 
export async function forgotPasswordController(request,response) {
    try {
        const { email } = request.body

        const user = await UserModel.findOne({ email })

        if(!user){
            return response.status(400).json({
                message : "email not available",
                error : true,
                success : false
            })
        }

        const otp = generatedOtp()
        const expireTime = new Date() + 60 * 60 * 1000

        const update = await UserModel.findByIdAndUpdate(user._id,{
            forgot_password_otp : otp,
            forgot_password_expiry : new Date(expireTime).toISOString()
        })

        await sendEmail({
            sendTo : email,
            subject : "Forgot Password",
            html : forgotPasswordTemplate({
                name : user.name,
                otp : otp
            })
        })
        
        return response.json({
            message : "check your email",
            error : false,
            success : true
        })

    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

//verify forgot password otp
export async function verifyForgotPasswordOtp(request,response) {
    try {
        const { email, otp } = request.body

        if(!email || !otp){
            return response.status(400).json({
                message : "provide require field email, otp.",
                error : true,
                success : false
            })
        }
        const user = await UserModel.findOne({ email })

        if(!user){
            return response.status(400).json({
                message : "email not available",
                error : true,
                success : false
            })
        }

        const currentTime = new Date().toISOString()

        if(user.forgot_password_expiry < currentTime){
            response.status(400).json({
                message : "otp expired",
                error : true,
                success : false
            })
        }

        if(otp !== user.forgot_password_otp){
            response.status(400).json({
                message : "Invalid otp",
                error : true,
                success : false
            })
        }

        return response.json({
            message : "Verify otp successfully",
            error : false,
            success : true
        })

    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })

    }
}

//reset the password
export async function resetpassword(request,response) {
    try {
        const { email, newPassword, confirmPassword } = request.body

        if(!email || !newPassword || !confirmPassword){
            response.status(400).json({
                message : "provide required field",

            })
        }

        const user = await UserModel.findOne({ email })

        if(!user){
            return response.status(400).json({
                message : "email is not available",
                error : true,
                success : false
            })
        }

        if(newPassword !== confirmPassword){
            return response.status(400).json({
                message : "newPassword and confirmPassword must be same.",
                error : true,
                success : false
            })
        }

        const salt = await bcryptjs.genSalt(10)
        const hashPassword = await bcryptjs.hash(newPassword, salt)
        
        const update = await UserModel.findByIdAndUpdate(user._id, {
            password : hashPassword
        })

        return response.json({
            message : "password updated successfully",
            error : false,
            success : true
        })

    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

//refresh token controller
export async function refreshToken(request,response) {
    try {
        const refreshToken = request.cookies.refreshToken || request?.header?.authorization?.split(" ")[1];

        if(!refreshToken){
            return response.status(401).json({
                message : "Invalid Token",
                error : true,
                success : false
            })
        }

        const verifyToken = await jwt.verify(refreshToken,process.env.SECRET_KEY_REFRESH_TOKEN)

        if(!verifyToken){
            return response.status(401).json({
                message : "token is expired",
                error : true,
                success : "false"
            })
        }

        const userId = verifyToken?._id

        const newAccessToken = await generatedAccessToken(userId)

        const cookiesOption = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }
        
        response.cookie('accessToken',newAccessToken,cookiesOption)

        return response.json({
            message : "new access token generated",
            error : false,
            success : true,
            data : {
                accessToken : newAccessToken
            }
        })

    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}
