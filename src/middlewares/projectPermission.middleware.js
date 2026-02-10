import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import { ProjectMember } from "../models/projectMember.models.js";
import mongoose from "mongoose";

export const validateProjectPermission = (roles = []) => {
    return asyncHandler(async (req,res,next)=>{
        const {projectId} = req.params;

        if(!projectId){
            throw new ApiError(400,"Project id is missing!");
        }

        const projectMember = await ProjectMember.findOne({
            project: new mongoose.Types.ObjectId(projectId),
            user: new mongoose.Types.ObjectId(req.user._id)
        });
        if(!projectMember){
            throw new ApiError(404,"Project member not found! ")
        }

        const givenRole = projectMember?.role

        req.user.role = givenRole;

        if(!roles.includes(givenRole)){
            throw new ApiError(403,"You dont have permission to perform this task!")
        }

        next();

    })
}