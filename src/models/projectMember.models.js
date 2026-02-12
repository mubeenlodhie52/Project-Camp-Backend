import mongoose from "mongoose";
const { Schema,  models } = mongoose;
import {AvailableUserRole,UserRolesEnum} from "../utils/constants.js";

const projectMemberSchema = new Schema({
    user:{
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true
    },
    project:{
        type:Schema.Types.ObjectId,
        ref: "Project",
        required: true
    },
    role:{
        type:String,
        enum:AvailableUserRole,
        default:UserRolesEnum.MEMBER
    }
},{timestamps:true});

export const ProjectMember = models.ProjectMember || mongoose.model("ProjectMember",projectMemberSchema)