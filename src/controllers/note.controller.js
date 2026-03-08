import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import mongoose from "mongoose";
import { ProjectNote } from "../models/note.models.js";
import { Project } from "../models/project.models.js";

const createNote = asyncHandler(async (req, res) => {
  const { content } = req.body;
  const { projectId } = req.params;
  const project = await Project.findById(projectId);

  if (!project) {
    throw new ApiError(404, "Project not found");
  }

  const note = await ProjectNote.create({
    project: new mongoose.Types.ObjectId(projectId),
    createdBy: new mongoose.Types.ObjectId(req.user._id),
    content,
  });

  return res
    .status(201)
    .json(new ApiResponse(201, note, "Project note created successfully!"));
});

const getAllNotes = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const project = await Project.findById(projectId);

  if (!project) {
    throw new ApiError(404, "Project not found");
  }

  const notes = await ProjectNote.find({ project: projectId }).populate(
    "createdBy",
    "username email",
  );
  return res
    .status(201)
    .json(
      new ApiResponse(200, notes, "All Project notes fetched successfully!"),
    );
});

const getNote = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { noteId } = req.params;

  const project = await Project.findById(projectId);

  if (!project) {
    throw new ApiError(404, "Project not found");
  }

  const note = await ProjectNote.findById(noteId).populate(
    "createdBy",
    "username email",
  );

  if (!note) {
    throw new ApiError(404, "Project Note not found");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, note, "Project Note fetched Successfully!"));
});

const updateNote = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { noteId } = req.params;
  const { content } = req.body;

  const project = await Project.findById(projectId);

  if (!project) {
    throw new ApiError(404, "Project not found");
  }

  const note = await ProjectNote.findById(noteId);

  if (!note) {
    throw new ApiError(404, "Project Note not found");
  }

  if (note.createdBy.toString() !== req.user._id.toString()) {
    throw new ApiError(403, "You cannot update the project note!");
  }

  note.content = content;
  await note.save();

  return res
    .status(200)
    .json(new ApiResponse(200, note, "Project Note Updated Successfully!"));
});

const deleteNote = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { noteId } = req.params;
  const project = await Project.findById(projectId);
  if (!project) {
    throw new ApiError(404, "Project not found");
  }

  const note = await ProjectNote.findById(noteId);

  if (!note) {
    throw new ApiError(404, "Project note not found");
  }

  if (note.createdBy.toString() !== req.user._id.toString()) {
    throw new ApiError(403, "You cannot delete this note");
  }

  await note.deleteOne();

  res
    .status(200)
    .json(new ApiResponse(200, null, "Project note deleted successfully"));
});

export { createNote, getAllNotes, getNote, updateNote, deleteNote };
