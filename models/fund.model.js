const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const fundSchema = new Schema({
    title: {
        type: String,
        required: true,
    },
    target: {
        type: String,
        required: true,
    },
    description: {
        type: String,
        required: true,
    },
    createdOn: {
        type: Date,
        default: Date.now,
    },
    endingDate: {
        type: Date,
        required: true,
        default: Date.now
    },
    budget: {
        type: Number,
        required: true,
    },
    fundImage: {
        type: String,
        required: true,
    },
    contactEmail: {
        type: String,
        required: true,
    },
    contactNumber: {
        type: String,
        required: true,
    },
    organizationID: {
        type: String,
        required: true,
    },
    status: {
        type: String,
        required: true,
        default: "pending"
    },
    donations: {
        type: Array,
        default: []
    },
    currentAmount: {
        type: Number,
        default: 0
    },
    completedOn: {
        type: Date,
        default: null
    }
})

const Fund = mongoose.model("Fund", fundSchema);
module.exports = Fund;