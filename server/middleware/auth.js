import jwt from 'jsonwebtoken'

const auth =async (request,response,next)=>{
    try {
        const token = request.cookies.accessToken || request?.header?.authorization.split(" ")[1];
        
        if(!token){
            return response.status(401).json({
                message : "Provide Token",

            })
        }

        const decode = await jwt.verify(token,process.env.SECRET_KEY_ACCESS_TOKEN)

        if(!decode){
            return response.status(401).json({
                message : "Unauthorized acccess",
                error : true,
                succcess : false
            })
        }

        request.userId = decode.id

        next()
        
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

export default auth;