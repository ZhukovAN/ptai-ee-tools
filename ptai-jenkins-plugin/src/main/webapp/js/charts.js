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

function createDistributionPieChart(chartDivId, option, i18map) {
    option.tooltip = { trigger: 'item' };
    option.series[0].itemStyle = {
        borderRadius: 3,
        borderColor: '#fff',
        borderWidth: 2
    };
    option.series[0].type = 'pie';
    option.series[0].radius = ['35%', '70%'];

    option.series[0].label = {
        normal: {
            formatter: '{c}',
            position: 'outside'
        },
        show: true
    };
    option.series[0].avoidLabelOverlap = true;

    option.series[0].data.forEach(function (item, index) {
        option.series[0].data[index].name = i18map[item.name].title
    }, option.series[0].data);

    option.legend = {
        orient: 'vertical',
        left: 'left',
    };
    var innerHeight = smallChartHeight;
    setupDivFrame(innerHeight, chartDivId, smallChartStyle);
    renderChart(chartDivId, option);
}

function createBuildHistoryChart(chartDivId, option, i18map, small = true) {
    option.title = { show: false };

    option.legend.top = 'top';
    option.legend.left = 'center';

    option.tooltip = {
        trigger: 'axis',
        axisPointer: {
            type: 'cross',
            label: {
                backgroundColor: '#6a7985'
            }
        }
    };

    option.grid = { bottom: 5, top: 35, left: 20, right: 10, containLabel: true };

    option.xAxis[0].type = 'category';
    option.xAxis[0].boundaryGap = true;
    option.xAxis[0].data.forEach(function (item, index) {
        this[index] = '#' + item;
    }, option.xAxis[0].data);
    option.xAxis[0].axisTick = { alignWithLabel: false }

    option.yAxis[0].type = 'value';
    option.yAxis[0].minInterval = 1;

    option.series.forEach(function (item, index) {
        item.type = 'bar';
        if (0 != index) {
            item.stack = '1';
            item.barWidth = small ? '20%': '15%';
        } else {
            item.barWidth = small ? '40%' : '30%';
        }
        item.itemStyle.borderColor = '#ffffff';
        item.itemStyle.borderWidth = 1;
        item.emphasis = { focus: 'series' };
        // Replace vulnerability level title values with localized captions
        item.name = i18map[item.name].title;
    });

    option.legend.data.forEach(function (item, index) {
        option.legend.data[index] = i18map[item].title;
    }, option.legend.data);

    var innerHeight = 250;
    setupDivFrame(innerHeight, chartDivId, small ? smallChartStyle : bigChartStyle);
    renderChart(chartDivId, option);
}

function createDurationHistoryChart(chartDivId, option) {
    option.title = { show: false };

    option.legend.top = 'top';
    option.legend.left = 'center';

    option.tooltip = {
        trigger: 'axis',
        axisPointer: {
            type: 'cross',
            label: {
                backgroundColor: '#6a7985'
            }
        }
    };

    option.grid = { bottom: 5, top: 35, left: 20, right: 10, containLabel: true };

    option.xAxis[0].type = 'category';
    option.xAxis[0].boundaryGap = true;
    option.xAxis[0].data.forEach(function (item, index) {
        this[index] = '#' + item;
    }, option.xAxis[0].data);
    option.xAxis[0].axisTick = { alignWithLabel: false }

    option.yAxis[0].type = 'value';
    option.yAxis[0].minInterval = 1;

    option.series.forEach(function (item, index) {
        item.type = 'line';
        item.step = 'middle';
    });

    var innerHeight = 250;
    setupDivFrame(innerHeight, chartDivId, bigChartStyle);
    renderChart(chartDivId, option);
}
