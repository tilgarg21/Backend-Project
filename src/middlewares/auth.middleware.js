import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { user } from "../models/user.model.js";

export const verifyJwt = asyncHandler(async (req, _, next)=> {
try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");
        if(!token){
            throw new apiError(401, "Unauthorized request");
        }
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    
        const User = await user.findById(decodedToken?._id).select(
            "-password -refreshToken"
        )
        if(!User){
            throw new apiError(401, "Invalid access token");
        }
    
        req.User = User;
        next();
} catch (error) {
    throw new apiError(401, error?.message || 
    "Invalid access token");
}
})