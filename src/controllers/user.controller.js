import { asyncHandler } from "../utils/asyncHandler.js";
import { apiError } from "../utils/apiError.js";
import { User } from "../models/user.model.js";
import {
  uploadOnCloudinary,
  deleteFromCloudinary,
} from "../utils/cloudinary.js";
import { apiResponse } from "../utils/apiResponse.js";
import Jwt from "jsonwebtoken";

// Generate Access and Refresh Tokens
const generateAccessAndRefreshTokens = async (userId) => {
  try {
    // Get user from DB to generate tokens
    // We fetch the user here to access instance methods (generateAccessToken / generateRefreshToken)
    const existingUser = await User.findById(userId);
    if (!existingUser) throw new apiError(404, "User not found");

    const accessToken = existingUser.generateAccessToken();
    const refreshToken = existingUser.generateRefreshToken();

    // Store refresh token in DB
    existingUser.refreshToken = refreshToken;
    await existingUser.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new apiError(
      500,
      "Something went wrong while generating refresh and access tokens"
    );
  }
};

// Register User
const registerUser = asyncHandler(async (req, res) => {
  const { fullName, email, username, password } = req.body;

  if (
    [fullName, email, password, username].some((field) => field?.trim() === "")
  ) {
    throw new apiError(400, "All fields are required");
  }

  const existedUser = await User.findOne({ $or: [{ username }, { email }] });
  if (existedUser)
    throw new apiError(409, "User with email or username already exists");

  const avatarLocalPath = req.files?.avatar?.[0]?.path;
  const coverImageLocalPath = req.files?.coverImage?.[0]?.path;
  if (!avatarLocalPath) throw new apiError(400, "Avatar file is required");

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = coverImageLocalPath
    ? await uploadOnCloudinary(coverImageLocalPath)
    : null;

  const newUser = await User.create({
    fullName,
    avatar: avatar.url,
    avatarPublicId: avatar.public_id,
    coverImage: coverImage?.url || "",
    coverImagePublicId: coverImage?.public_id || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(newUser._id).select(
    "-password -refreshToken"
  );
  if (!createdUser)
    throw new apiError(500, "Something went wrong while registering the user");

  return res
    .status(201)
    .json(new apiResponse(200, createdUser, "User registered successfully"));
});

// Login User
const loginUser = asyncHandler(async (req, res) => {
  const { email, username, password } = req.body;
  if (!(username || email))
    throw new apiError(400, "Username or Email required");

  const existingUser = await User.findOne({ $or: [{ username }, { email }] });
  if (!existingUser) throw new apiError(404, "User doesn't exist");

  const isPasswordValid = await existingUser.isPasswordCorrect(password);
  if (!isPasswordValid) throw new apiError(404, "Invalid user credentials");

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    existingUser._id
  );
  const loggedInUser = await User.findById(existingUser._id).select(
    "-password -refreshToken"
  );

  const options = { httpOnly: true, secure: true };
  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new apiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "User logged in successfully"
      )
    );
});

// Logout User
const logoutUser = asyncHandler(async (req, res) => {
  // Remove refresh token from DB to invalidate session
  await User.findByIdAndUpdate(req.user._id, {
    $set: { refreshToken: undefined },
  });

  const options = { httpOnly: true, secure: true };
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new apiResponse(200, {}, "User logged out"));
});

// Refresh Access Token
const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;
  if (!incomingRefreshToken) throw new apiError(401, "Unauthorized request");

  try {
    const decodedToken = Jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    // Fetch user to validate refresh token
    // We need to fetch from DB because the token in DB may have changed or been invalidated
    const existingUser = await User.findById(decodedToken?._id);
    if (!existingUser) throw new apiError(401, "Invalid refresh token");

    if (incomingRefreshToken !== existingUser.refreshToken) {
      throw new apiError(401, "Refresh token is expired or used");
    }

    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessAndRefreshTokens(existingUser._id);
    const options = { httpOnly: true, secure: true };

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new apiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed successfully"
        )
      );
  } catch (error) {
    throw new apiError(401, error?.message || "Invalid refresh token");
  }
});

// Change Current Password
const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  // Fetch user to verify old password
  const existingUser = await User.findById(req.user._id);

  const isPasswordCorrect = await existingUser.isPasswordCorrect(oldPassword);
  if (!isPasswordCorrect) throw new apiError(400, "Invalid old password");

  existingUser.password = newPassword;
  await existingUser.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new apiResponse(200, {}, "Password changed successfully"));
});

// Get Current User
const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new apiResponse(200, req.user, "Current user fetched successfully"));
});

// Update Account Details
const updateAccountDetails = asyncHandler(async (req, res) => {
  const { fullName, email } = req.body;
  if (!fullName || !email) throw new apiError(400, "All fields are required");

  // Fetch user to update their details
  const updatedUser = await User.findByIdAndUpdate(
    req.user._id,
    { $set: { fullName, email } },
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(
      new apiResponse(200, updatedUser, "Account details updated successfully")
    );
});

// Update User Avatar
const updateUserAvatar = asyncHandler(async (req, res) => {
  const avatarLocalPath = req.file?.path;
  if (!avatarLocalPath) throw new apiError(400, "Avatar file is missing");

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  if (!avatar.url) throw new apiError(400, "Error while uploading the avatar");

  // Fetch existing user to delete old avatar if it exists
  const existingUser = await User.findById(req.user._id);
  if (!existingUser) throw new apiError(404, "User not found");

  if (existingUser.avatarPublicId) {
    try {
      await deleteFromCloudinary(existingUser.avatarPublicId);
    } catch (error) {
      console.log(error.message);
    }
  }

  const updatedUser = await User.findByIdAndUpdate(
    req.user._id,
    { $set: { avatar: avatar.url, avatarPublicId: avatar.public_id } },
    { new: true }
  ).select("-password");

  res
    .status(200)
    .json(new apiResponse(200, updatedUser, "Avatar updated successfully"));
});

// Update Cover Image
const updateCoverImage = asyncHandler(async (req, res) => {
  const coverImageLocalPath = req.file?.path;
  if (!coverImageLocalPath) throw new apiError(400, "Cover image is missing");

  const coverImage = await uploadOnCloudinary(coverImageLocalPath);
  if (!coverImage.url)
    throw new apiError(400, "Error while uploading the cover image");

  // Fetch existing user to delete old cover image if it exists
  const existingUser = await User.findById(req.user._id);
  if (!existingUser) throw new apiError(404, "User not found");

  if (existingUser.coverImagePublicId) {
    try {
      await deleteFromCloudinary(existingUser.coverImagePublicId);
    } catch (error) {
      console.log(error.message);
    }
  }

  const updatedUser = await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        coverImage: coverImage.url,
        coverImagePublicId: coverImage.public_id,
      },
    },
    { new: true }
  ).select("-password");

  res
    .status(200)
    .json(
      new apiResponse(200, updatedUser, "Cover Image updated successfully")
    );
});

const getUserChannelProfile = asyncHandler(async (req, res) => {
  const { username } = req.params;
  if (!username?.trim()) {
    throw new apiError(400, "Username is missing");
  }

  const channel = await User.aggregate([
    {
      $match: {
        username: username?.toLowerCase(),
      },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers",
      },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribedTo",
      },
    },
    {
      $addFields: {
        subscribersCount: {
          $size: "$subscribers",
        },
        channelsSubscribedToCount: {
          $size: "$subscribedTo",
        },
        isSubscribed: {
          $cond: {
            if: { $in: [req.user?._id, "$subscribers.subscriber"] },
            then: true,
            else: false,
          },
        },
      },
    },
    {
      $project: {
        fullName: 1,
        username: 1,
        subscribersCount: 1,
        channelsSubscribedToCount: 1,
        isSubscribed: 1,
        avatar: 1,
        coverImage: 1,
        email: 1,
      },
    },
  ]);
  console.log(channel);
  if(!channel?.length){
    throw new apiError(404, "Channel doesn't exist");
  }

  return res.status(200)
  .json(new apiResponse(200, 
    channel[0], 
    "User channel fetched successfully"));
});

const getWatchHistory = asyncHandler(async (req, res)=> {
  const user = await User.aggregate([
    {
      $match: {
        _id: new mongoose.Types.ObjectId(req.user._id)
      }
    },
    {
      $lookup: {
      from: "videos",
      localField: "watchHistory",
      foreignField: "_id",
      as: "watchHistory" ,
      pipeline: [
        {
          $lookup: {
            from: "users",
            localField: "owner",
            foreignField: "_id",
            as: "owner",
            pipeline: [
              {
                $project: {
                  fullName: 1,
                  username: 1,
                  avatar: 1
                }
              }
            ]
          }
        },
        {
          $addFields: {
            owner: {
              $first: "$owner"
            }
          }
        }
      ]
    }
  }
  ])

  return res.status(200)
.json(new apiResponse(200,
  user[0].watchHistory,
  "Watch history fetched successfully"
))
})



export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateCoverImage,
  getUserChannelProfile,
  getWatchHistory
  
};
