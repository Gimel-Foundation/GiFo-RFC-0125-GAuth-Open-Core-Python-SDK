import { Router, type IRouter } from "express";
import healthRouter from "./health";
import gauthMgmtRouter from "./gauth-mgmt";

const router: IRouter = Router();

router.use(healthRouter);
router.use("/gauth/mgmt/v1", gauthMgmtRouter);

export default router;
