/**
 * Renders a trend chart in the specified div using ECharts.
 *
 * @param {String} chartDivId - the ID of the div where the chart should be shown in
 * @param {JSON} chartModel - the stacked line chart model
 */
function renderChart(chartDivId, chartModel) {
    var chart = echarts.init(document.getElementById(chartDivId));

    chart.setOption(chartModel);
    chart.resize();
    window.onresize = function() {
        chart.resize();
    };
}

function textWidth(text, font) {
    let canvas = document.getElementById('computedTextWidth');
    if (!canvas) {
        canvas = document.createElement('canvas');
        canvas.id = 'computedTextWidth';
        canvas.style.cssText = 'visibility: hidden; position: absolute; left: -999em; top:-999em;';
        document.body.appendChild(canvas);
    }
    const context = canvas.getContext('2d');
    context.font = font;
    context.fillText(text, 0, 0);
    return context.measureText(text).width;
}

function maxTextWidth(strings, font) {
    var widths = strings.map(title => textWidth(title, font))
    return widths.reduce(function(a, b) { return Math.max(a, b); }, 0)
}

function generateSeverityDistributionTrendChart() {
}

