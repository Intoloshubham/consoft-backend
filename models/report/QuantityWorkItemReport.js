import { ObjectId } from "mongodb";
import mongoose from "mongoose";

const quantityWorkItemReportSchema = mongoose.Schema({
    quantity_report_id:{ type: ObjectId },
    item_id: { type: ObjectId }, 
    nos: { type: Number, default:null }, 
    unit_name: { type: String }, 
    steel_mm: { type: Number, default:null }, //for steel  
    num_length: { type: Number }, 
    unit_name:{type:String},
    num_width: { type: Number }, 
    num_height: { type: Number }, 
    num_total: { type: Number }, 
    remark: { type: String },
    quality_type : { type: String},
    subquantityitems:[{
        sub_nos: { type: Number, default:null },
        sub_steel_mm: { type: Number, default:null }, //for steel 
        sub_length: { type: Number }, 
        sub_width: { type: Number }, 
        sub_height: { type: Number }, 
        sub_total: { type: Number }, 
        sub_remark: { type: String },
        sub_quality_type : { type: String },
    }]
});

export default mongoose.model('QuantityWorkItemReport', quantityWorkItemReportSchema, 'quantityWorkItemReports');