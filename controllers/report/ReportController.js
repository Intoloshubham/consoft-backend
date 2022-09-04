import CustomErrorHandler from "../../services/CustomErrorHandler.js";
import CustomSuccessHandler from "../../services/CustomSuccessHandler.js";
import CustomFunction from "../../services/CustomFunction.js";
import { reportSchema } from "../../validators/index.js";
import { Report } from "../../models/index.js";
import Constants from "../../constants/index.js";
import QuantityReportController from './QuantityReportController.js';
import ManpowerReportController from "./ManpowerReportController.js";
import { ObjectId } from "mongodb";


const ReportController = {

    async saveReport(req, res, next){

        // const {error} = reportSchema.validate(req.body);
        // if(error){
        //     return next(error);
        // }

        // const company = {
        //     _id
        // }
        // req.company = company;
        // next()

        // console.log(req.body);
        // return;

        try {
            let current_date = CustomFunction.currentDate();
            let current_time = CustomFunction.currentTime();
            // let sta_date = "2022/08/23"
            const {company_id, project_id, user_id} = req.body;
            const exist = await Report.exists({company_id:company_id, project_id:project_id, user_id:user_id, report_date:current_date});
            let report_id ;
           
            if (!exist) {
                const report = new Report({
                    company_id:company_id,
                    project_id:project_id,
                    user_id:user_id,
                    report_date:current_date,
                    report_time:current_time,
                }) ;
                const result = await report.save();
                report_id = result._id;
            }else{
                report_id = exist._id;
            }
            let bodyData;
            switch (req.params.type) {
                case Constants.MANPOWER:
                    const {contractor_id,manpowerCategories} = req.body;
                    bodyData = {
                        report_id:report_id,
                        user_id:user_id,
                        contractor_id:contractor_id,
                        manpowerCategories:manpowerCategories,
                    }
                    ManpowerReportController.store(bodyData).then((result)=>{
                        if (result.status === Constants.RES_SUCCESS) {
                            res.send(CustomSuccessHandler.success('Manpower report created successfully'))
                        }else{
                            return (result.error);
                        }
                    });
                    break;
                case Constants.STOCK:
                    console.log("Stock")
                    break;
                case Constants.QUANTITY:
                    const {inputs} = req.body;
                    bodyData = {
                        report_id:report_id,
                        user_id:user_id,
                        inputs:inputs,
                    }
                    
                    QuantityReportController.store(bodyData).then((result, err)=>{
                        if (result.status === Constants.RES_SUCCESS) {
                            res.send(CustomSuccessHandler.success('Quantity item report created successfully'))
                        }else{
                            return (err);
                        }
                    });
                    break;
                case Constants.TANDP:
                    console.log("TAndP")
                    break;

                default:
                    console.log("Nothing to match")
                    break;
            }

            // use another controller function here
        } catch (err) {
            return next(err);
        }

        
        

        // try {
        //     // res.status(200).send({ "status": "success", "message": "Project created" })
        //     res.send(CustomSuccessHandler.success('Report created successfully'));
        // } catch (err) {
        //     return next(err);
        // }

        // const data = QuantityReportController.index(); //final call
        // console.log(data);
    },

    // async index(req, res, next){
    //     const documents = await Report.aggregate([
    //         {
    //             $match: { 
    //                 // "project_id": ObjectId("62c827499c1d4cb814ead624"),
    //                 "project_id": ObjectId(req.params.project_id) 
    //             }
    //         },
    //         {
    //            $lookup:{
    //               from:"manpowerReports",
    //               localField:'_id',
    //               foreignField:"report_id",
    //               as:"manpowerReportsData"
    //             }
    //         },
    //         {$unwind:"$manpowerReportsData"},
         
    //         {
    //             $lookup: {
    //                 from: "manpowerMemberReports",
    //                 let: { "manpower_report_id": "$manpowerReportsData._id" },
    //                 pipeline: [
    //                     {
    //                         $match: {
    //                             $expr: { $eq: ["$manpower_report_id", "$$manpower_report_id"] }
    //                         }
    //                     },
    //                 ],
    //                 as: 'manpowerMemberReportData'
    //             }
    //         },
    //         {$unwind: "$manpowerMemberReportData"},
        
    //         {
    //             $lookup: {
    //                 from: "contractors",
    //                 localField: "manpowerReportsData.contractor_id",
    //                 foreignField: "_id",
    //                 as: 'contractorData'
    //             }
    //         },
    //         {$unwind:"$contractorData"},
    //         {
    //                         $lookup:{
    //                                   from:"manpowerCategories",
    //                                   let: { "manpower_category_id": "$manpowerMemberReportData.manpower_category_id".toString()},
    //                                   pipeline: [
    //                                               {
    //                                                 $match: {
    //                                                     $expr: { $eq: ["$_id", "$$manpower_category_id"] }
    //                                                         }
    //                                               },
    //                                           ],
    //                                   as: 'manpowerCateg'
                            
    //                                   }
    //         },
            
    //         {$unwind: "$manpowerCateg"},
        
    //         {
    //             $lookup:{ 
    //                       from:"manpowerSubCategories",
    //                       let:{"manpower_sub_category_id":"$manpowerMemberReportData.manpower_sub_category_id".toString()},
    //                       pipeline:[
    //                                   {
    //                                     $match:{
    //                                       $expr:{$eq:["$_id","$$manpower_sub_category_id"]}
    //                                     }    
    //                                   }
    //                                 ],
    //                         as:"manpowerSubCateg"
    //                     }
    //         },
    //         {$unwind:"$manpowerSubCateg"},
    //         {
    //                     $lookup: { 
    //                           from: 'quantityReports',
    //                           localField: '_id',
    //                           foreignField: 'report_id',
    //                           as: 'quantityReport'
    //                         }
    //         },
    //         {
    //                   $unwind: "$quantityReport"
    //         },
    //           {
    //                 $lookup: {
    //                     from: "quantityWorkItemReports",
    //                     let: { "quantity_report_id": "$quantityReport._id" },
    //                     pipeline: [
    //                         {
    //                             $match: {
    //                                 $expr: { $eq: ["$quantity_report_id", "$$quantity_report_id"] }
    //                             }
    //                         },
    //                     ],
    //                     as: 'quantityWorkItems'
    //                 }
    //             },
    //             {
    //                 $unwind: "$quantityWorkItems"
    //             },
    //           {
    //               $lookup: {
    //                   from: "quantityReportItems",
    //                   localField: "quantityWorkItems.item_id",
    //                   foreignField: "_id",
    //                   as: 'itemsName'
    //               }
    //             },
    //             {
    //                 $unwind: "$itemsName"
    //             },
        
    //         {
    //               $group:{
    //                   _id: "$_id" ,
    //                   "report_id": { "$first": "$report_id" },
    //                   "contractor_id": { "$first": "$contractorData._id" },
    //                   "company_id":{"$first":"$company_id"},
    //                   "project_id":{"$first":"$project_id"},
    //                   "contractor_name": { "$first": "$contractorData.contractor_name" },
    //                   "manpower_category_id_new": { $addToSet : "$manpowerMemberReportData.manpower_category_id" },
    //                   "manpowerCategories":{$addToSet:'$manpowerMemberReportData'},
    //                   "manpowers": { "$push": { manpower_category: "$manpowerCateg.manpower_category",
    //                                         manpower_sub_category: "$manpowerSubCateg.manpower_sub_category",
    //                                         manpower_category_id:"$manpowerCateg._id",
    //                                         manpower_sub_category_id:"$manpowerSubCateg._id"
    //                   } },        
    //                   "quantityReport":{$addToSet:"$quantityReport"},            
    //                   "quantityWorkItems":{$addToSet:"$quantityWorkItems"}            
             
    //               }
    //           },
        
        
          
    //           {
    //               $project: {
    //                   _id: "$_id",
    //                   report_id:"$_id",
    //                   project_id:"$project_id",
    //                   contractor_id: "$contractor_id",
    //                   contractor_name: "$contractor_name",
    //                   manpowerCategories:[{
    //                       manpower_category_id: "$manpower_category_id_new",
    //                         "members": {
    //                           "$map": {
    //                             "input": "$manpowerCategories",
    //                             "in": {
    //                               "$let": {
    //                                 "vars": {
    //                                   "m": {
    //                                     "$arrayElemAt": [
    //                                       {
    //                                         "$filter": {
    //                                           "input": "$manpowers",
    //                                           "cond": {
    //                                             "$eq": [
    //                                               "$$mb.manpower_category_id",
    //                                               "$$this.manpower_category_id"
    //                                             ]
    //                                           },
    //                                           "as": "mb"
    //                                         }
    //                                       },
    //                                       0
    //                                     ]
    //                                   }
    //                                 },
    //                                 "in": {
    //                                   "$mergeObjects": [
    //                                     "$$this",
    //                                     {
    //                                       "manpower_category": "$$m.manpower_category",
    //                                       "manpower_sub_category":"$$m.manpower_sub_category"
    //                                     }
    //                                   ]
    //                                 }
    //                               }
    //                             }
    //                           }
    //                         }
    //                   }],
                      
    //                   "quantityReport":{
    //                     "$map": {
    //                         "input": "$quantityReport", 
    //                         "in": {
    //                           "$let": {
    //                             "vars": {
    //                               "m": {
    //                                 "$arrayElemAt": [
    //                                   {
    //                                     "$filter": {
    //                                       "input": "$quantityWorkItems",
    //                                       "cond": {
    //                                         "$eq": [
    //                                           "$$mb.quantity_report_id",
    //                                           "$$this._id"
    //                                         ]
    //                                       },
    //                                       "as": "mb"
    //                                     }
    //                                   },
    //                                   0
    //                                 ]
    //                               }
    //                             },
    //                             "in": {
    //                               "$mergeObjects": [
    //                                 "$$this",
    //                                 {
                                      
    //                                   "quality_type": "$$m.quality_type",
    //                                   "item_name":"$$m.item_name",
    //                                   "quantity_report_id":"$$m.quantity_report_id",
    //                                   "item_id":"$$m.item_id",
    //                                   "unit_name":"$$m.unit_name",
    //                                   "num_length":"$$m.num_length",
    //                                   "num_width":"$$m.num_width",
    //                                   "num_height":"$$m.num_height",
    //                                   "num_total":"$$m.num_total",
    //                                   "remark":"$$m.remark",
    //                                   "subquantityitems":"$$m.subquantityitems"
        
    //                                 }
    //                               ]
    //                             }
    //                           }
    //                         }
    //                       }
    //                   },
        
    //               }
    //           }
    //         ]);

    //     return res.json({ "status": 200, data:documents });

    // },

    async index(req, res, next){
        let documents
        try {
            
            documents = await Report.aggregate([
                {
                    $match: {
                        // $and: [
                        //     { "project_id": ObjectId(req.params.project_id) },
                        // ]
                        "project_id": ObjectId(req.params.project_id),
                        // "user_id": ObjectId(req.params.user_id),
                        // "report_date": req.params.date
                    }
                    
                },
                {
                    $lookup: { 
                        from: 'users',
                        localField: 'user_id',
                        foreignField: '_id',
                        as: 'userData'
                    }
                },
                {$unwind:"$userData"},
                {
                    $lookup: { 
                        from: 'projects',
                        localField: 'project_id',
                        foreignField: '_id',
                        as: 'projectData'
                    }
                },
                {$unwind:"$projectData"},
                // {
                //     $lookup: { 
                //         from: 'manpowerReports',
                //         localField: '_id',
                //         foreignField: 'report_id',
                //         as: 'manpowerReportData'
                //     }
                // },
                // {$unwind:"$manpowerReportData"},
                // {
                //     $lookup: {
                //         from: "contractors",
                //         localField: "manpowerReportData.contractor_id",
                //         foreignField: "_id",
                //         as: 'contractorData'
                //     }
                // },
                // {$unwind:"$contractorData"},
                // {
                //     $lookup: {
                //         from: "manpowerMemberReports",
                //         let: { "manpower_report_id": "$manpowerReportData._id" },
                //         pipeline: [
                //             {
                //                 $match: {
                //                     $expr: { $eq: ["$manpower_report_id", "$$manpower_report_id"] }
                //                 }
                //             },
                //         ],
                //         as: 'manpowerMemberReportData'
                //     }
                // },
                // {$unwind: "$manpowerMemberReportData"},
                // {
                //     $group:{
                //         _id: "$manpowerMemberReportData.manpower_report_id" ,
                //         "company_id": { "$first": "$company_id" },
                //         "project_id": { "$first": "$project_id" },
                //         "user_id": { "$first": "$manpowerReportData.user_id" },
                //         "user_name": { "$first": "$userData.name" },
                //         "contractor_id": { "$first": "$manpowerReportData.contractor_id" },
                //         "contractor_name": { "$first": "$contractorData.contractor_name" },
                //         "manpower_category_id_new": { $addToSet : "$manpowerMemberReportData.manpower_category_id" },
                //         "manpowerCategories":{"$push":'$manpowerMemberReportData'}
                //     }
                // },
                {
                    $project: {
                        _id: 1, 
                        company_id: 1,     
                        project_id: 1,
                        project_name: "$projectData.project_name",
                        user_id: "$user_id",
                        user_name: "$userData.name",
                        report_date: 1,
                        report_time: 1,
                        verify_1_status: 1,
                        verify_1_date: 1,
                        verify_1_time: 1,
                        verify_1_revert: 1,
                        verify_1_revert_msg: 1,
                        verify_2_status: 1,
                        verify_2_date: 1,
                        verify_2_time: 1,
                        verify_2_revert: 1,
                        verify_2_revert_msg: 1,
                        admin_3_status: 1,
                        admin_3_date: 1,
                        admin_3_time: 1,
                        admin_3_revert: 1,
                        admin_3_revert_msg: 1,
                        admin_2_status: 1,
                        admin_2_date: 1,
                        admin_2_time: 1,
                        admin_2_revert: 1,
                        admin_2_revert_msg: 1,
                        admin_1_status: 1,
                        admin_1_date: 1,
                        admin_1_time: 1,
                        admin_1_revert: 1,
                        admin_1_revert_msg: 1,
                        report_status: 1
                        // contractor_id: "$contractor_id",
                        // contractor_name: "$contractor_name",
                        // manpowerReport:[{
                        //     manpower_category_id: "$manpower_category_id_new",
                        //     members:"$manpowerCategories"
                        // }]
                    }
                },
            ]);
        } catch (err) {
            return next(err);
        }
        return res.json({ "status": 200, data:documents });

    },

    async verifyReport(req, res, next){
        let current_date = CustomFunction.currentDate();
        let current_time = CustomFunction.currentTime();

        try {
            const document = await Report.findById({_id:req.params.id});
            console.log(document)
        } catch (err) {
            return next(err);
        }
        
    },

}

export default ReportController;