var ptaiCharts = []
/**
 * Renders a trend chart in the specified div using ECharts.
 *
 * @param {String} chartDivId - the ID of the div where the chart should be shown in
 * @param {JSON} chartModel - the stacked line chart model
 */
function renderChart(chartDivId, chartModel) {
    var chart = echarts.init(document.getElementById(chartDivId));
    const self = this;
    self.ptaiCharts.push(chart);

    chart.setOption(chartModel);
    chart.resize();

    window.onresize = function() {
        self.ptaiCharts.forEach((obj) => {
            obj.resize();
        });
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

function setupDivFrame(innerHeight, divId, initialStyle) {
    const chartDivPadding = { top: 16, bottom: 16, left: 12, right: 12 };
    const chartDivBorder = { top: 1, bottom: 1, left: 4, right: 1 };
    const chartDivColor = {
        top: 'rgb(230, 230, 230)', bottom: 'rgb(230, 230, 230)',
        left: 'rgb(116, 116, 116)', right: 'rgb(230, 230, 230)'
    };
    var divHeight = innerHeight + chartDivPadding.top + chartDivBorder.top + chartDivPadding.bottom + chartDivBorder.bottom;
    var divStyle = initialStyle + "height: " + divHeight + "px; "
    for (var side in chartDivPadding)
        divStyle += 'padding-' + side + ": " + chartDivPadding[side] + "px; ";
    for (var side in chartDivBorder) {
        divStyle += 'border-' + side + "-width: " + chartDivBorder[side] + "px; ";
        divStyle += 'border-' + side + "-style: solid; ";
    }
    for (var side in chartDivColor)
        divStyle += 'border-' + side + "-color: " + chartDivColor[side] + "; ";
    $(divId).setAttribute("style", divStyle);
}
