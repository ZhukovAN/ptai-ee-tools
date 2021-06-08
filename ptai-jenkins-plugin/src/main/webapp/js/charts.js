/**
 * Renders a trend chart in the specified div using ECharts.
 *
 * @param {String} chartDivId - the ID of the div where the chart should be shown in
 * @param {JSON} chartModel - the stacked line chart model
 */
function renderTrendChart(chartDivId, chartModel) {
    var chart = echarts.init(document.getElementById(chartDivId));

    chart.setOption(chartModel);
    chart.resize();
    window.onresize = function() {
        chart.resize();
    };
}
