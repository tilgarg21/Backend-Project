import { asyncHandler } from "../utils/asyncHandler.js";
import { apiError } from "../utils/apiError.js";
import { user } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { apiResponse } from "../utils/apiResponse.js";
import Jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async(userId)=> {
    try{
        const User = await user.findById(userId);
        const accessToken = User.generateAccessToken();
        const refreshToken = User.generateRefreshToken();

        User.refreshToken = refreshToken;
        await User.save({validateBeforeSave: false});

        return {accessToken, refreshToken};
    }
    catch(error){
        throw new apiError(500, "Something went wrong while generating refresh and access tokens");
    }
}
const registerUser = asyncHandler(async (req, res)=> {
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, check for avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    const { fullName, email, username, password } = req.body;
    // console.log("email:", email);

    if(
        [fullName, email, password, username].some((field)=>
        field?.trim() === "")
    ){
        throw new apiError(400, "All fields are required");
    }

    const existedUser = await user.findOne({
        $or: [{username}, {email}]
    })
    if(existedUser){
        throw new apiError(409, "User with email or username already exists");
    }
    const avatarLocalPath = req.files?.avatar?.[0]?.path;
    const coverImageLocalPath = req.files?.coverImage?.[0]?.path;

    if(!avatarLocalPath){
        throw new apiError(400, "Avatar file is required");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if(!avatar){
         throw new apiError(400, "Avatar file is required");
    }

    const User = await user.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })
    const createdUser = await user.findById(User._id).select(
        "-password -refreshToken"
    )
    if(!createdUser){
        throw new apiError(500, "Something went wrong while registering the user");
    }
    return res.status(201).json(
        new apiResponse(200, createdUser, "User registed successfully")
    )
})

const loginUser = asyncHandler(async (req, res)=> {
    // req body -> data
    // username or email
    // find the user
    // password check
    // access and refresh token generation
    // send cookies

    const {email, username, password} = req.body;
    console.log(email);

    // if(!username && !email){
    //     throw new apiError(400, "Username and Email required");
    // }
    // here is an alternative of above code based on logic discussion
    if(!(username || email)){
       throw new apiError(400, "Username and Email required");
    }

    const User = await user.findOne({
        $or: [{username}, {email}]
    })
    if(!User){
        throw new apiError(404, "User dosesn't exist");
    }
    const isPasswordValid = await User.isPasswordCorrect(password);
    if(!isPasswordValid){
        throw new apiError(404, "Invalid user credentials");
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(User._id);

    const loggedInUser = await user.findById(User._id).
    select("-password -refreshToken");

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200).
    cookie("accessToken", accessToken, options).
    cookie("refreshToken", refreshToken, options).
    json(new apiResponse(200, {
        User: loggedInUser, accessToken,
        refreshToken
    },
    "User logged in successfully"
))
})

const logoutUser = asyncHandler(async (req, res)=> {
    await user.findByIdAndUpdate(
        req.User._id,
        {
            $set: {refreshToken: undefined}
        },
        {
            new: true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }
    return res.
    status(200).
    clearCookie("accessToken", options).
    clearCookie("refreshToken", options).
    json(new apiResponse(200, {}, "User logged out"));
})

const refreshAccessToken = asyncHandler(async (req, res)=> {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;
    if(!incomingRefreshToken){
        throw new apiError(401, "Unauthorized request")
    }

try {
        const decodedToken = Jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
        const User = await user.findById(decodedToken?._id); 
        if(!User){
            throw new apiError(401, "Invalid refresh token");
        }
    
        if(incomingRefreshToken !== user?.refreshToken){
            throw new apiError(401, "Refresh token is expired or used");
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await 
        generateAccessAndRefreshTokens(User._id);
    
        return res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(new apiResponse(
            200, {accessToken, refreshToken: newRefreshToken},
            "Access token refreshed successfully"
        ))
} catch (error) {
    throw new apiError(401, error?.message ||
        "Invalid refresh token"
    )
}
})
export { registerUser, loginUser, logoutUser, refreshAccessToken }


