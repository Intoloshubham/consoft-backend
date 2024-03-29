import Joi from "joi";
import { voucher, voucherDetails } from "../../models/index.js";
import CustomErrorHandler from "../../services/CustomErrorHandler.js";
import CustomSuccessHandler from "../../services/CustomSuccessHandler.js";
import CustomFunction from "../../services/CustomFunction.js";
import { ObjectId } from "mongodb";
import helpers from "../../helpers/index.js";
import constants from "../../constants/index.js";
const VoucherController = {
  async index(req, res, next) {
    let documents;
    try {
      documents = await voucher.aggregate([
        {
          $match: {
            company_id: ObjectId(req.params.company_id),
            voucher_date: req.params.date,
          },
        },
        {
          $lookup: {
            from: "voucherDetails",
            localField: "_id",
            let: {
              id: "_id",
              voucher_type: req.params.voucher_type,
              // voucher_type: constants.PURCHASED_VOUCHER,
              verify_status: false,
              revert_status: false,
            },
            pipeline: [
              {
                $match: {
                  $expr: {
                    $and: [
                      { $eq: ["$voucher_type", "$$voucher_type"] },
                      { $eq: ["$verify_status", "$$verify_status"] },
                      { $eq: ["$revert_status", "$$revert_status"] },
                    ],
                  },
                },
              },
            ],
            foreignField: "voucher_id",
            as: "voucherData",
          },
        },
        {
          $unwind: "$voucherData",
        },
        {
          $lookup: {
            from: "items",
            localField: "voucherData.item_id",
            foreignField: "_id",
            as: "itemData",
          },
        },
        {
          $unwind: "$itemData",
        },
        {
          $lookup: {
            from: "projects",
            localField: "project_id",
            foreignField: "_id",
            as: "projectData",
          },
        },
        {
          $unwind: "$projectData",
        },
        {
          $group: {
            _id: "$project_id",
            company_id: { $first: "$company_id" },
            project_id: { $first: "$project_id" },
            project_name: { $first: "$projectData.project_name" },
            voucherData: {
              $push: {
                _id: "$voucherData._id",
                voucher_id: "$voucherData.voucher_id",
                project_id: "$project_id",
                voucher_type: "$voucherData.voucher_type",
                verify_status: "$voucherData.verify_status",
                revert_status: "$voucherData.revert_status",
                item_id: "$voucherData.item_id",
                voucher_date: "$voucher_date",
                item_name: "$itemData.item_name",
                qty: "$voucherData.qty",
                vehicle_no: "$voucherData.vehicle_no",
                location: "$voucherData.location",
                remark: "$voucherData.remark",
              },
            },
          },
        },
        {
          $project: {
            _id: "$_id",
            verify_status: "$verify_status",
            company_id: "$company_id",
            // project_id: "$project_id",
            project_name: "$project_name",
            voucherData: "$voucherData",
          },
        },
      ]);
      return res.json({ status: 200, data: documents });
    } catch (error) {
      return next(error);
    }
  },
  async getAllVoucher(req, res, next) {
    let documents;
    try {
      documents = await voucher.aggregate([
        {
          $match: {
            company_id: ObjectId(req.params.company_id),
            voucher_date: req.params.date,
          },
        },
        {
          $lookup: {
            from: "voucherDetails",
            localField: "_id",          
            foreignField: "voucher_id",
            as: "voucherData",
          },
        },
        {
          $unwind: "$voucherData",
        },
        {
          $lookup: {
            from: "items",
            localField: "voucherData.item_id",
            foreignField: "_id",
            as: "itemData",
          },
        },
        {
          $unwind: "$itemData",
        },
        {
          $lookup: {
            from: "units",
            localField: "voucherData.unit_id",
            foreignField: "_id",
            as: "unitData",
          },
        },
        {
          $unwind: "$unitData",
        },
        {
          $lookup: {
            from: "projects",
            localField: "project_id",
            foreignField: "_id",
            as: "projectData",
          },
        },
        {
          $unwind: "$projectData",
        },
        {
          $group: {
            _id: "$project_id",
            company_id: { $first: "$company_id" },
            project_id: { $first: "$project_id" },
            project_name: { $first: "$projectData.project_name" },
            voucherData: {
              $push: {
                _id: "$voucherData._id",
                voucher_id: "$voucherData.voucher_id",
                project_id: "$project_id",
                voucher_type: "$voucherData.voucher_type",
                verify_status: "$voucherData.verify_status",
                revert_status: "$voucherData.revert_status",
                item_id: "$voucherData.item_id",
                unit_name: "$unitData.unit_name",
                unit_id: "$unitData._id",
                voucher_date: "$voucher_date",
                item_name: "$itemData.item_name",
                qty: "$voucherData.qty",
                vehicle_no: "$voucherData.vehicle_no",
                location: "$voucherData.location",
                remark: "$voucherData.remark",
              },
            },
          },
        },
        {
          $project: {
            _id: "$_id",
            verify_status: "$verify_status",
            company_id: "$company_id",
            // project_id: "$project_id",
            project_name: "$project_name",
            voucherData: "$voucherData",
          },
        },
      ]);
      return res.json({ status: 200, data: documents });
    } catch (error) {
      return next(error);
    }
  },
  async filterVoucher(req, res, next) {
    let documents;
    try {
      documents = await voucher.aggregate([
        {
          $match: {
            company_id: ObjectId(req.params.company_id),
            voucher_date: req.params.date,
          },
        },
        {
          $lookup: {
            from: "voucherDetails",
            localField: "_id",
            let: {
              id: "_id",
              voucher_type: req.params.voucher_type,
              // voucher_type: constants.PURCHASED_VOUCHER,
              // verify_status: false,
              // revert_status: false,
            },
            pipeline: [
              {
                $match: {
                  $expr: {
                    $and: [
                      { $eq: ["$voucher_type", "$$voucher_type"] },
                      // { $eq: ["$verify_status", "$$verify_status"] },
                      // { $eq: ["$revert_status", "$$revert_status"] },
                    ],
                  },
                },
              },
            ],
            foreignField: "voucher_id",
            as: "voucherData",
          },
        },
        {
          $unwind: "$voucherData",
        },
        {
          $lookup: {
            from: "items",
            localField: "voucherData.item_id",
            foreignField: "_id",
            as: "itemData",
          },
        },
        {
          $unwind: "$itemData",
        },
        {
          $lookup: {
            from: "units",
            localField: "voucherData.unit_id",
            foreignField: "_id",
            as: "unitData",
          },
        },
        {
          $unwind: "$unitData",
        },
        {
          $lookup: {
            from: "projects",
            localField: "project_id",
            foreignField: "_id",
            as: "projectData",
          },
        },
        {
          $unwind: "$projectData",
        },
        {
          $group: {
            _id: "$project_id",
            company_id: { $first: "$company_id" },
            project_id: { $first: "$project_id" },
            project_name: { $first: "$projectData.project_name" },
            voucherData: {
              $push: {
                _id: "$voucherData._id",
                voucher_id: "$voucherData.voucher_id",
                project_id: "$project_id",
                voucher_type: "$voucherData.voucher_type",
                verify_status: "$voucherData.verify_status",
                revert_status: "$voucherData.revert_status",
                item_id: "$voucherData.item_id",
                unit_id: "$unitData._id",
                unit_name: "$unitData.unit_name",
                voucher_date: "$voucher_date",
                item_name: "$itemData.item_name",
                qty: "$voucherData.qty",
                vehicle_no: "$voucherData.vehicle_no",
                location: "$voucherData.location",
                remark: "$voucherData.remark",
              },
            },
          },
        },
        {
          $project: {
            _id: "$_id",
            verify_status: "$verify_status",
            company_id: "$company_id",
            // project_id: "$project_id",
            project_name: "$project_name",
            voucherData: "$voucherData",
          },
        },
      ]);
      return res.json({ status: 200, data: documents });
    } catch (error) {
      return next(error);
    }
  },

  // async edit(req, res, next) {
  //   let document;
  //   try {
  //     document = await voucherDetails
  //       .findOne({
  //         _id: req.params.id,
  //       })
  //       .select("-__v");
  //   } catch (err) {
  //     return next(CustomErrorHandler.serverError());
  //   }

  //   return res.json({ status: 200, data: document });
  // },

  async update(req, res, next) {
    let document;
    const {
      item_id,
      qty,
      voucher_type,
      vehicle_no,
      unit_id,
      location,
      remark,
      project_id,
      company_id,
    } = req.body;
    try {
      document = await voucherDetails
        .findByIdAndUpdate(
          {
            _id: ObjectId(req.params.id),
          },
          {
            item_id,
            unit_id,
            qty,
            voucher_type,
            verify_status:
              voucher_type == constants.PURCHASED_VOUCHER ? false : true,
            vehicle_no,
            location,
            remark,
          },
          {
            new: true,
          }
        )
        .select("-createdAt -updatedAt -__v");
      if (
        constants.RECEIVED_VOUCHER == document.voucher_type ||
        constants.RECEIVED_RETURN_VOUCHER == document.voucher_type
      ) {
        const avail = await helpers.availableStock(
          document.voucher_type,
          document._id,
          company_id,
          project_id
        );
      }
    } catch (error) {
      return next(error);
    }
    // res.status(200).json(document);
    res.send({ status: 200, data: document });
  },

  async verifiedVoucher(req, res, next) {
    let documents;
    try {
      documents = await voucher.aggregate([
        {
          $match: {
            company_id: ObjectId(req.params.company_id),
            voucher_date: req.params.date,
          },
        },
        {
          $lookup: {
            from: "voucherDetails",
            localField: "_id",
            let: { id: "_id", verify_status: true },
            pipeline: [
              {
                $match: {
                  $expr: {
                    $and: [
                      { $eq: ["$verify_status", "$$verify_status"] },
                      // { $eq: [ "$voucher_id", "$$id" ] }
                    ],
                  },
                },
              },
            ],
            foreignField: "voucher_id",
            as: "voucherData",
          },
        },
        {
          $unwind: "$voucherData",
        },
        {
          $lookup: {
            from: "items",
            localField: "voucherData.item_id",
            foreignField: "_id",
            as: "itemData",
          },
        },
        {
          $unwind: "$itemData",
        },
        {
          $lookup: {
            from: "projects",
            localField: "project_id",
            foreignField: "_id",
            as: "projectData",
          },
        },
        {
          $unwind: "$projectData",
        },
        {
          $group: {
            _id: "$project_id",
            company_id: { $first: "$company_id" },
            // project_id: { $first: "$project_id" },
            project_name: { $first: "$projectData.project_name" },
            voucherData: {
              $push: {
                _id: "$voucherData._id",
                voucher_id: "$voucherData.voucher_id",
                project_id: "$project_id",
                voucher_type: "$voucherData.voucher_type",
                verify_status: "$voucherData.verify_status",
                revert_status: "$voucherData.revert_status",
                item_id: "$voucherData.item_id",
                voucher_date: "$voucher_date",
                item_name: "$itemData.item_name",
                qty: "$voucherData.qty",
                vehicle_no: "$voucherData.vehicle_no",
                location: "$voucherData.location",
                remark: "$voucherData.remark",
              },
            },
          },
        },
        {
          $project: {
            _id: "$_id",
            // verify_status: "$verify_status",
            // revert_status:"$revert_status",
            company_id: "$company_id",
            // project_id: "$project_id",
            project_name: "$project_name",
            voucherData: "$voucherData",
          },
        },
      ]);
      return res.json({ status: 200, data: documents });
    } catch (error) {
      return next(error);
    }
  },
  async revertedVoucher(req, res, next) {
    let documents;
    try {
      documents = await voucher.aggregate([
        {
          $match: {
            company_id: ObjectId(req.params.company_id),
            voucher_date: req.params.date,
          },
        },
        {
          $lookup: {
            from: "voucherDetails",
            localField: "_id",
            let: { id: "_id", revert_status: true },
            pipeline: [
              {
                $match: {
                  $expr: {
                    $and: [
                      { $eq: ["$revert_status", "$$revert_status"] },
                      // { $eq: [ "$voucher_id", "$$id" ] }
                    ],
                  },
                },
              },
            ],
            foreignField: "voucher_id",
            as: "voucherData",
          },
        },
        {
          $unwind: "$voucherData",
        },
        {
          $lookup: {
            from: "items",
            localField: "voucherData.item_id",
            foreignField: "_id",
            as: "itemData",
          },
        },
        {
          $unwind: "$itemData",
        },
        {
          $lookup: {
            from: "projects",
            localField: "project_id",
            foreignField: "_id",
            as: "projectData",
          },
        },
        {
          $unwind: "$projectData",
        },
        {
          $group: {
            _id: "$project_id",
            company_id: { $first: "$company_id" },
            // project_id: { $first: "$project_id" },
            project_name: { $first: "$projectData.project_name" },
            voucherData: {
              $push: {
                _id: "$voucherData._id",
                voucher_id: "$voucherData.voucher_id",
                project_id: "$project_id",
                voucher_type: "$voucherData.voucher_type",
                verify_status: "$voucherData.verify_status",
                revert_status: "$voucherData.revert_status",
                item_id: "$voucherData.item_id",
                voucher_date: "$voucher_date",
                item_name: "$itemData.item_name",
                qty: "$voucherData.qty",
                vehicle_no: "$voucherData.vehicle_no",
                location: "$voucherData.location",
                remark: "$voucherData.remark",
              },
            },
          },
        },
        {
          $project: {
            _id: "$_id",
            // verify_status: "$verify_status",
            // revert_status:"$revert_status",
            company_id: "$company_id",
            // project_id: "$project_id",
            project_name: "$project_name",
            voucherData: "$voucherData",
          },
        },
      ]);
      return res.json({ status: 200, data: documents });
    } catch (error) {
      return next(error);
    }
  },

  async store(req, res, next) {
    const {
      voucher_type,
      item_id,
      unit_id,
      location,
      vehicle_no,
      qty,
      remark,
      company_id,
      project_id,
    } = req.body;
    // console.log("-body", req.body);
    let current_date = CustomFunction.currentDate();
    let current_time = CustomFunction.currentTime();
    const voucherData = new voucher({
      company_id,
      project_id,
      voucher_date: current_date,
      voucher_time: current_time,
    });
    const exist = await voucher.exists({
      company_id: company_id,
      project_id: project_id,
      // voucher_type: voucher_type,
      voucher_date: current_date,
    });
    if (exist) {
      const voucherDetail = voucherDetails({
        voucher_id: exist._id,
        item_id: item_id,
        unit_id:unit_id,
        location: location,
        voucher_type: voucher_type,
        verify_status:
          voucher_type == constants.PURCHASED_VOUCHER
            ? // voucher_type == constants.RECEIVED_VOUCHER
              false
            : true,
        vehicle_no: vehicle_no,
        qty: qty,
        remark: remark,
      });
      const temp = await voucherDetail.save();
      if (
        constants.RECEIVED_VOUCHER == temp.voucher_type ||
        constants.RECEIVED_RETURN_VOUCHER == temp.voucher_type
      ) {
        const avail = await helpers.availableStock(
          temp.voucher_type,
          temp._id,
          company_id,
          project_id
        );
      }
    } else {
      const result = await voucherData.save();
      const voucherId = result._id;
      const voucherDetail = voucherDetails({
        voucher_id: voucherId,
        item_id: item_id,
        unit_id:unit_id,
        location: location,
        voucher_type: voucher_type,
        verify_status:
          voucher_type == constants.PURCHASED_VOUCHER
            ? // voucher_type == constants.RECEIVED_VOUCHER
              false
            : true,
        vehicle_no: vehicle_no,
        qty: qty,
        remark: remark,
      });
      const temp = await voucherDetail.save();
      if (
        constants.RECEIVED_VOUCHER == temp.voucher_type ||
        constants.RECEIVED_RETURN_VOUCHER == temp.voucher_type
      ) {
        const avail = await helpers.availableStock(
          temp.voucher_type,
          temp._id,
          company_id,
          project_id
        );
      }
    }

    try {
      res.send(CustomSuccessHandler.success("voucher created successfully"));
    } catch (err) {
      return next(err);
    }
  },
  async verifyVoucher(req, res, next) {
    let documents;
    try {
      documents = await voucherDetails.findByIdAndUpdate(
        {
          _id: ObjectId(req.params.id),
        },
        {
          verify_status: true,
          revert_status: false,
        },
        {
          new: true,
        }
      );
      // console.log("🚀 ~ file: VoucherController.js ~ line 284 ~ verifyVoucher ~ documents", documents)
      // if (documents.verify_status == true) {
      // const temp = await helpers.availableStock(
      //   documents.voucher_type,
      //   documents._id
      // );
      // }
      res.json({ status: 200, data: documents });
    } catch (error) {
      return next(error);
    }
  },
  async revertVoucher(req, res, next) {
    let documents;
    try {
      documents = await voucherDetails.findByIdAndUpdate(
        {
          _id: req.params.id,
        },
        {
          revert_status: true,
        },
        {
          new: true,
        }
      );
      res.json({ status: 200, data: documents });
    } catch (error) {
      return next(error);
    }
  },
};
export default VoucherController;
