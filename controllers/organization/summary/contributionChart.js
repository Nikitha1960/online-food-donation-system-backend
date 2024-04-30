const FundDonation = require("../../../models/fundDonation.model");

const contributionChart = async (req, res) => {
    const { organizationID } = req.params;
    const result = {
        labels: [],
        data: [],
    }
    const chartData = []

    try {
        await FundDonation.find({
            organizationID: organizationID
        }).then(async (contributions) => {
            const months = new Set();
            for (const contribution of contributions) {
                months.add(contribution.donatedDate.getMonth()+1);
            }
            for (const month of months) {
                result.labels.push(month);
                result.data.push(0);
            }
            for (const contribution of contributions) {
                const index = result.labels.indexOf(contribution.donatedDate.getMonth()+1);
                result.data[index] += contribution.amount;
            }

            for (let i = 1; i <= 12; i++) {
                if (result.labels.includes(i)) {
                    chartData.push(result.data[result.labels.indexOf(i)]);
                } else {
                    chartData.push(0);
                }

            }
            res.status(200).send({
                chartData: chartData
            })
        }).catch((err) => {
            res.status(500).send({
                msg: "Error fetching data",
                error: err,
            });
        });
    } catch (error) {
        console.log(error);
    }
}

module.exports = {
    contributionChart
}