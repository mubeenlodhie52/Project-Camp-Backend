import { User } from "../models/user.models.js";
import { Project } from "../models/project.models.js";
import { Task } from "../models/task.models.js";
import { SubTask } from "../models/subTask.models.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import mongoose, { Mongoose } from "mongoose";
import { AvailableUserRole, UserRolesEnum } from "../utils/constants.js";

const getTasks = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const project = await Project.findById(projectId);
  if (!project) {
    throw new ApiError(404, "Project not found");
  }

  const tasks = await Task.find({
    project: new mongoose.Types.ObjectId(projectId),
  }).populate("assignedTo", "avatar username fullName");

  return res
    .status(201)
    .json(new ApiResponse(200, tasks, "Tasks fetched successfully"));
});

const createTask = asyncHandler(async (req, res) => {
  const { title, description, assignedTo, status } = req.body;
  const { projectId } = req.params;
  const project = await Project.findById(projectId);

  if (!project) {
    throw new ApiError(404, "Project not found");
  }

  const files = req.files || [];

  const attachments = files.map((file) => {
    return {
      url: `${process.env.SERVER_URL}/images/${file.filename}`,
      mimeType: file.mimetype,
      size: file.size,
    };
  });

  const task = await Task.create({
    title,
    description,
    project: new mongoose.Types.ObjectId(projectId),
    assignedTo: assignedTo
      ? new mongoose.Types.ObjectId(assignedTo)
      : undefined,
    status,
    assignedBy: new mongoose.Types.ObjectId(req.user._id),
    attachments,
  });

  return res
    .status(201)
    .json(new ApiResponse(201, task, "Task created successfully"));
});

const getTaskById = asyncHandler(async (req, res) => {
  const { taskId } = req.params;

  const task = await Task.aggregate([
    {
      $match: {
        _id: new mongoose.Types.ObjectId(taskId),
      },
    },
    {
      $lookup: {
        from: "users",
        localField: "assignedTo",
        foreignField: "_id",
        as: "assignedTo",
        pipeline: [
          {
            $project: {
              _id: 1,
              username: 1,
              fullName: 1,
              avatar: 1,
            },
          },
        ],
      },
    },
    {
      $lookup: {
        from: "subtasks",
        localField: "_id",
        foreignField: "task",
        as: "subtasks",
        pipeline: [
          {
            $lookup: {
              from: "users",
              localField: "createdBy",
              foreignField: "_id",
              as: "createdBy",
              pipeline: [
                {
                  $project: {
                    _id: 1,
                    username: 1,
                    fullName: 1,
                    avatar: 1,
                  },
                },
              ],
            },
          },
          {
            $addFields: {
              createdBy: { $arrayElemAt: ["$createdBy", 0] },
            },
          },
        ],
      },
    },
    {
      $addFields: {
        assignedTo: { $arrayElemAt: ["$assignedTo", 0] },
      },
    },
  ]);

  if (!task || task.length === 0) {
    throw new ApiError(404, "Task not found");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, task[0], "Task fetched successfully"));
});

const updateTask = asyncHandler(async (req, res) => {
  const { taskId } = req.params;
  const {title, description, status, assignedTo} = req.body
  const task = await Task.findByIdAndUpdate(
    taskId,
    {
      title,
      description,
      status,
      assignedTo: new mongoose.Types.ObjectId(assignedTo)
    }
  )

  if(!task){
    throw new ApiError(404,"Task not found!")
  }

  return res.status(200).json(new ApiResponse(200,task,"Task updated successfully!"))
});

const deleteTask = asyncHandler(async (req, res) => {
  const {taskId} = req.params;
  const task = await Task.findById(taskId);
  if(!task){
    throw new ApiError(404,"Task not found!")
  }
  await SubTask.deleteMany({task : task._id});
  await task.deleteOne();

  return res.status(200).json(new ApiResponse(200,null,"Task deleted sucessfully!"));

});

const createSubTask = asyncHandler(async (req, res) => {
  const {title,isCompleted} = req.body;
  const {taskId} = req.params;
  const task = await Task.findById(taskId);

  if(!task){
    throw new ApiError(404,"Task not found!");
  }

  const subTask = await SubTask.create(
    {
      title,
      task : new mongoose.Types.ObjectId(taskId),
      isCompleted,
      createdBy: new mongoose.Types.ObjectId(req.user._id)
    }
  )

  return res.status(201).json(new ApiResponse(201, subTask, "SubTask created successfully!"));
});

const updateSubTask = asyncHandler(async (req, res) => {
  const {title,isCompleted} = req.body;
  const {subtaskId} = req.params;
  const subTask = await SubTask.findByIdAndUpdate(
    subtaskId,
    {
      title,
      isCompleted
    },
    {new:true}
  )
  if(!subTask){
    throw new ApiError(404,"SubTask not found!")
  }

  res.status(200).json(new ApiResponse(200,subTask,"SubTask updated successfully!"))
  
});

const deleteSubTask = asyncHandler(async (req, res) => {
  const {subtaskId} = req.params;
  const subTask = await SubTask.findByIdAndDelete(subtaskId);

  if(!subTask){
    throw new ApiError(404,"SubTask not found!");
  }

  return res.status(200).json(new ApiResponse(200,"SubTask deleted successfully!"));
});

export {
  getTasks,
  createTask,
  getTaskById,
  updateTask,
  deleteTask,
  createSubTask,
  updateSubTask,
  deleteSubTask,
};
