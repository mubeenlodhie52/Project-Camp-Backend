import { Router } from "express";
import {
  getTasks,
  createTask,
  getTaskById,
  updateTask,
  deleteTask,
  createSubTask,
  updateSubTask,
  deleteSubTask
} from "../controllers/task.controller.js";

import { verifyJwt } from "../middlewares/auth.middleware.js";
import { validateProjectPermission } from "../middlewares/projectPermission.middleware.js";
import { UserRolesEnum, AvailableUserRole } from "../utils/constants.js";

const router = Router({ mergeParams: true });

router.use(verifyJwt);

router.get(
  "/",
  validateProjectPermission(AvailableUserRole),
  getTasks
);

router.post(
  "/",
  validateProjectPermission([UserRolesEnum.ADMIN]),
  createTask
);

router.get(
  "/:taskId",
  validateProjectPermission(AvailableUserRole),
  getTaskById
);

// UPDATE task
// router.put(
//   "/:taskId",
//   validateProjectPermission([UserRolesEnum.ADMIN]),
//   updateTask
// );

// // DELETE task
// router.delete(
//   "/:taskId",
//   validateProjectPermission([UserRolesEnum.ADMIN]),
//   deleteTask
// );


//   SUBTASK ROUTES

// // CREATE subtask
// router.post(
//   "/:taskId/subtasks",
//   validateProjectPermission(AvailableUserRole),
//   createSubTask
// );

// // UPDATE subtask
// router.put(
//   "/:taskId/subtasks/:subtaskId",
//   validateProjectPermission(AvailableUserRole),
//   updateSubTask
// );

// // DELETE subtask
// router.delete(
//   "/:taskId/subtasks/:subtaskId",
//   validateProjectPermission([UserRolesEnum.ADMIN]),
//   deleteSubTask
// );

export default router;
