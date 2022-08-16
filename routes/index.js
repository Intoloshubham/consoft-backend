import express from "express";
const router = express.Router();

import {
    //auth
    loginController, refreshController, userController,

    //company
    CompanyController, ProductKeyController, UserRoleController,

    //project
    ProjectCategoryController, ProjectTypeController, ProjectController, ProjectTeamController,

    //Assignwork
    AssignWorkController, UserAssignWorkController,

    //stock
    UnitController, ItemController, ManageStockController, ContractorController, ManageBoqController,

    //checklist
    ChecklistOptionTypeController, ChecklistOptionController, ChecklistController, ToolsMachineryController,

    //report 
    ReportController, QuantityReportController, QuantityReportItemController, QualityTypeController, ManpowerCategoryController, ManpowerSubCategoryController,

    //supplier
    SupplierController,

    //revert
    RevertController, VerifyController, AttendanceController,

    //water level
    WaterLevelController


} from '../controllers/index.js';

//company
import auth from '../middlewares/auth.js';
import admin from '../middlewares/admin.js';

import adminEditor from "../middlewares/adminEditor.js";

//user
import user_auth from '../middlewares/user_auth.js';

// router.get('/me', userController.me);
router.post('/login', loginController.login);

router.post('/company-login', CompanyController.companyLogin);
router.get('/company', [auth, admin], CompanyController.index);
router.post('/company', CompanyController.store);

router.post('/verify-product-key', ProductKeyController.verifyProductKey);

router.post('/register', userController.register);
router.get('/user', user_auth, userController.user);
router.get('/users/:company_id', userController.index);

router.get('/role-by-users/:role_id', userController.roleByUsers);

router.post('/refresh', refreshController.refresh);
router.post('/logout', auth, loginController.logout);

//role
router.get('/role/:company_id', UserRoleController.index);
router.post('/role', UserRoleController.store);
router.get('/role/:id', UserRoleController.edit);
router.put('/role/:id', UserRoleController.update);
router.delete('/role/:id', UserRoleController.destroy);

//project category
router.get('/project-category/:company_id', ProjectCategoryController.index);
router.post('/project-category', ProjectCategoryController.store);
router.get('/project-category/:id', ProjectCategoryController.edit);
router.put('/project-category/:id', ProjectCategoryController.update);
router.delete('/project-category/:id', ProjectCategoryController.destroy);

router.get('/project-type/:company_id', ProjectTypeController.index);
router.get('/project-type-by-category/:category_id', ProjectTypeController.getProjectTypeByCategory);
router.post('/project-type', ProjectTypeController.store);
router.get('/project-type/:id', ProjectTypeController.edit);
router.put('/project-type/:id', ProjectTypeController.update);
router.delete('/project-type/:id', ProjectTypeController.destroy);

//project 
router.get('/projects/:company_id', ProjectController.index);
router.post('/projects', ProjectController.store);
router.get('/projects/:id', ProjectController.edit);
router.put('/projects/:id', ProjectController.update);
router.delete('/projects/:id', ProjectController.destroy);

router.get('/user-by-projects/:user_id', ProjectController.userByProjects);


//project team
router.get('/project-team/:id', ProjectTeamController.index);
router.post('/project-team', ProjectTeamController.store);
router.delete('/project-team/:project_id/:user_id', ProjectTeamController.destroy);

router.get('/project-team-role-wise/:project_id', ProjectTeamController.projectTeamRoleWise);//pending

//stock
router.get('/unit', UnitController.index);
router.post('/unit', UnitController.store);
router.get('/unit/:id', UnitController.edit);
router.put('/unit/:id', UnitController.update);
router.delete('/unit/:id', UnitController.destroy);

router.get('/item', ItemController.index);
router.post('/item', ItemController.store);
router.get('/item/:id', ItemController.edit);
router.put('/item/:id', ItemController.update);
router.delete('/item/:id', ItemController.destroy);

router.get('/stock-entry', ManageStockController.index);
router.post('/stock-entry', ManageStockController.store);
router.get('/stock-entry/:id', ManageStockController.edit);
router.put('/stock-entry/:id', ManageStockController.update);

//boq
router.get('/manage-boq/:company_id/:project_id?', ManageBoqController.index);
router.post('/manage-boq', ManageBoqController.store);
router.get('/edit-manage-boq/:id/:item_id', ManageBoqController.edit);//pending
router.put('/manage-boq/:id/:item_id', ManageBoqController.update);

// router.put('/products/:id', [auth, admin], productController.update);
// router.delete('/products/:id', [auth, admin], productController.destroy);
// router.get('/products', productController.index);
// router.get('/products/:id', productController.show);

//const BASE_IMG_URL = "http://sdplaccount.sdplweb.com/storage/app/public/";
//const BASE_IMG_URL = "http://192.168.1.98:99/sdpl-account/storage/app/public/";

//Checklist items
router.get('/checklist-option-type', [auth, adminEditor], ChecklistOptionTypeController.index);
// router.get('/checklist-option-type', ChecklistOptionTypeController.index);
// router.get('/checklist-option-type/:company_id', ChecklistOptionTypeController.index);
router.post('/checklist-option-type', ChecklistOptionTypeController.store);
router.get('/checklist-option-type/:id', ChecklistOptionTypeController.edit);
router.put('/checklist-option-type/:id', ChecklistOptionTypeController.update);
router.delete('/checklist-option-type/:id', ChecklistOptionTypeController.destroy);

router.get('/checklist-option', ChecklistOptionController.index);
router.post('/checklist-option', ChecklistOptionController.store);
router.get('/checklist-option/:id', ChecklistOptionController.edit);
router.put('/checklist-option/:id', ChecklistOptionController.update);
router.delete('/checklist-option/:id', ChecklistOptionController.destroy);

router.get('/checklists/:company_id', ChecklistController.index);
router.post('/checklists', ChecklistController.store);
router.get('/checklists/:id', ChecklistController.edit);
router.put('/checklists/:id', ChecklistController.update);
router.delete('/checklists/:id', ChecklistController.destroy);

//AssignWork
router.get('/assign-works', AssignWorkController.assignWork);
router.get('/submit-works/:company_id', AssignWorkController.submitWork);
router.post('/assign-works', AssignWorkController.store);
router.get('/assign-works/:id', AssignWorkController.edit);
router.put('/assign-works/:id', AssignWorkController.update);
// router.delete('/assign-works/:id',AssignWorkController.destroy);
router.get('/verify-revert-works/:company_id', AssignWorkController.verifyRevertWorks);
router.delete('/sub-assign-work/:id', AssignWorkController.destroySubAssignWork);

//user-end assignwork
router.get('/user-assign-works/:user_id', UserAssignWorkController.index)
router.put('/user-submit-work/:work_id', UserAssignWorkController.userSubmitWork)
router.get('/user-completed-works/:user_id', UserAssignWorkController.userCompletedWork)
// router.put('/user-assign-works/:id',UserAssignWorkController.update)
router.put('/user-work-comment/:work_id', UserAssignWorkController.userWorkComment)

//Tools And Machinery
router.get('/tools-machinery', ToolsMachineryController.index);
router.post('/tools-machinery', ToolsMachineryController.store);
router.get('/tools-machinery/:id', ToolsMachineryController.edit);
router.put('/tools-machinery/:id', ToolsMachineryController.update);
router.delete('/tools-machinery/:id', ToolsMachineryController.destroy);

//contractors
router.get('/contractor', ContractorController.index);
router.get('/project-by-contractor/:project_id', ContractorController.projectByContractor);
router.post('/contractor', ContractorController.store);
router.delete('/contractor/:contractor_id', ContractorController.destroy);

//report
router.post('/report/:type', ReportController.saveReport);

    router.get('/quantity-report/:user_id/:project_id/:user_date', QuantityReportController.index);    

    router.get('/edit-quantity-report/:id', QuantityReportController.edit);
    router.put('/quantity-report/:id', QuantityReportController.update);

    // router.post('/quantity-report',QuantityReportController.store);
    router.get('/quantity-item-exist/:project_id/:user_id', QuantityReportController .quantityItemExist);
    
    // report item
    router.get('/quantity-report-item/:company_id', QuantityReportItemController.index);
    router.post('/quantity-report-item', QuantityReportItemController.store);
    router.get('/edit-quantity-report-item/:id', QuantityReportItemController.edit);
    router.put('/update-quantity-report-item/:id', QuantityReportItemController.update);
    router.delete('/delete-quantity-report-item/:id', QuantityReportItemController.destroy);

    //quality type
    router.get('/quality-type/', QualityTypeController.index);
    router.post('/quality-type/', QualityTypeController.store);
    router.get('/quality-type/:id', QualityTypeController.edit);
    router.put('/quality-type/:id', QualityTypeController.update);
    router.delete('/quality-type/:id', QualityTypeController.destroy);

    //manpower category
    router.get('/manpower-category/:company_id', ManpowerCategoryController.index);
    router.post('/manpower-category', ManpowerCategoryController.store);
    router.get('/edit-manpower-category/:id', ManpowerCategoryController.edit);
    router.put('/manpower-category/:id', ManpowerCategoryController.update);
    router.delete('/manpower-category/:id', ManpowerCategoryController.destroy);

    //manpower sub category
    // router.get('/manpower-sub-category/:manpower_category_id', ManpowerSubCategoryController.index);
    router.get('/manpower-sub-category/:company_id', ManpowerSubCategoryController.index);
    router.post('/manpower-sub-category', ManpowerSubCategoryController.store);
    router.get('/edit-manpower-sub-category/:id', ManpowerSubCategoryController.edit);
    router.put('/manpower-sub-category/:id', ManpowerSubCategoryController.update);
    router.delete('/manpower-sub-category/:id', ManpowerSubCategoryController.destroy);

router.get('/supplier', SupplierController.index);
router.post('/supplier', SupplierController.store);
router.get('/supplier/:supplier_id', SupplierController.edit);
router.put('/supplier/:supplier_id', SupplierController.update);
router.delete('/supplier/:supplier_id', SupplierController.destroy);

//revert
router.put('/revert-submit-work/:work_id', RevertController.revertSubmitWork);

//verify
router.get('/verify-submit-work/:work_id', VerifyController.verifySubmitWork);

//user profile
router.get('/attendance/:user_id', AttendanceController.attendance);
// router.post('/attendance', AttendanceController.attendance);

router.get('/leaves', AttendanceController.getLeaves);
router.post('/apply-leaves', AttendanceController.applyLeaves);
router.put('/approve-leaves/:id', AttendanceController.approveLeaves);

//water level
// router.get('/water-level/:led_status', WaterLevelController.waterLevel);
router.post('/water-level', WaterLevelController.waterLevel);



export default router;
