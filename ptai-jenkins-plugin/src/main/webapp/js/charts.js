var charts = []

const chartDimensions = {
    /**
     * Chart bar height, pixels
     */
    barHeight: 25,
    bottomMargin: 20,
    axisLabelMargin: 8,
    axisFontFamily: 'verdana',
    axisFontSize: '12px',
}

/**
 * Renders a chart in the specified div using ECharts. Adds newly created chart
 * to onresize event handler to rearrange charts when window size is changed
 * @param {String} chartDivId - the ID of the div where the chart should be shown in
 * @param {JSON} chartModel - the stacked line chart model
 */
function renderChart(chartDivId, chartModel) {
    var chart = echarts.init(document.getElementById(chartDivId));
    const self = this;
    self.charts.push(chart);

    chart.setOption(chartModel);
    chart.resize();

    window.onresize = function() {
        self.charts.forEach((obj) => {
            obj.resize();
        });
    };
}

/**
 * Calculate width of text rendered using assigned font
 * @param text Text that width is to be returned
 * @param font Font used for text render
 * @returns {*} Text width in pixels
 */
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

/**
 * Get maximum width of text array items
 * @param strings Array of strings
 * @param font Font used for text render
 * @returns {*} Maximum text width in pixels
 */
function maxTextWidth(strings, font) {
    var widths = strings.map(title => textWidth(title, font))
    return widths.reduce(function(a, b) { return Math.max(a, b); }, 0)
}

/**
 * Get maximum width of text array items
 * @param strings Array of strings
 * @param font Font used for text render
 * @returns {*} Maximum text width in pixels
 */
function maxChartTextWidth(strings) {
    var widths = strings.map(title => textWidth(title, chartDimensions.axisFontSize + " " + chartDimensions.axisFontFamily))
    return widths.reduce(function(a, b) { return Math.max(a, b); }, 0)
}

/**
 * Function sets DIV height for its inner contents to exactly fit desired value
 * @param innerHeight Height of DIV internals
 * @param divId DIV id to set height
 */
function setFrameHeight(innerHeight, divId) {
    var style = getComputedStyle(document.getElementById(divId));
    var divHeight = innerHeight;
    divHeight += parseInt(style.paddingTop) + parseInt(style.paddingBottom);
    divHeight += parseInt(style.borderTopWidth) + parseInt(style.borderBottomWidth);
    // Setup chart DIV height
    document.getElementById(divId).style.height = divHeight + 'px';
}

function hide(divId) {
    document.getElementById(divId).style.display = "none";
}

/**
 * Function initializes and renders bar chart inside dedicated DIV. If chart data is
 * empty then "NO DATA" placeholder will be shown instead of chart
 * @param chartDivId DIV id where chart is to be rendered. If option contain no data,
 * chartDivId+"-no-data" DIV will be used as placeholder
 * @param option Chart data
 * @param maxTextWidth Maximum width of Y axis label. Used to place chart grid's left
 * margin at specific offset when two or more charts are to be placed in straight
 * vertical line
 */
function createDistributionBarChart(chartDivId, option, maxTextWidth) {
    if (0 === option.series[0].data.length) {
        // Show "NO DATA" placeholder instead of chart if there's no data
        hide(chartDivId);
        // Use fixed 36px height
        setFrameHeight(36, chartDivId + "-no-data", false);
        return;
    }
    option.tooltip = { trigger: 'axis', axisPointer: { type: 'shadow' } };
    option.xAxis[0] = Object.assign(option.xAxis[0], {
        type: 'value', minInterval: 1
    })
    option.yAxis[0].type = 'category';
    option.series[0].type = 'bar';
    // No space from top, margin defined by div. Also use maxTextWidth to shift Y axis
    option.grid = {
        left: maxTextWidth + chartDimensions.axisLabelMargin + "px",
        top: "0px",
        bottom: chartDimensions.bottomMargin + "px" };
    // Hide "NO DATA placeholder"
    hide(chartDivId + "-no-data");
    // Calculate chart's DIV inner height ...
    var innerHeight = option.yAxis[0].data.length * chartDimensions.barHeight + chartDimensions.bottomMargin;
    // ... and stretch DIV vertically to fit chart
    setFrameHeight(innerHeight, chartDivId, false);
    // Render chart finally
    renderChart(chartDivId, option);
}

/**
 * Function initializes and renders pie chart in the dedicated DIV using chart data
 * @param chartDivId
 * @param option
 * @param i18map
 */
function createDistributionPieChart(chartDivId, option, i18map = null) {
    if (0 === option.series[0].data.length) {
        // Show "NO DATA" placeholder instead of chart if there's no data
        hide(chartDivId);
        // Use fixed 36px height
        setFrameHeight(36, chartDivId + "-no-data", false);
        return;
    }

    // Merge data with representation-related parameters
    option = Object.assign(option, {
        tooltip: { trigger: 'item' },
        legend: {
            orient: 'vertical',
            left: 'left',
        }
    });

    option.series[0] = Object.assign(option.series[0], {
        itemStyle: {
            borderRadius: 3,
            borderColor: '#fff',
            borderWidth: 2
        },
        type: 'pie',
        radius: ['35%', '70%'],
        label: {
            normal: {
                formatter: '{c}',
                position: 'outside'
            },
            show: true
        },
        avoidLabelOverlap: true
    });

    // If i18n map defined, replace names
    if (null != i18map) {
        option.series[0].data.forEach(function (item, index) {
            option.series[0].data[index].name = i18map[item.name].title
        }, option.series[0].data);
    }

    // Hide "NO DATA placeholder"
    hide(chartDivId + "-no-data");
    renderChart(chartDivId, option);
}

/**
 * Function initializes and renders trend area chart inside dedicated DIV. If chart data is
 * empty then nothing will be rendered
 * @param chartDivId DIV id where chart is to be rendered
 * @param option Chart data
 */
function createTrendChart(chartDivId, option) {
    /*
    if (0 === option.series[0].data.length) {
        // Show "NO DATA" placeholder instead of chart if there's no data
        document.getElementById(chartDivId).hide();
        // Use fixed 36px height
        setFrameHeight(36, chartDivId + "-no-data", false);
        return;
    }
    */
    option = Object.assign(option, {
        title: { show: false },
        legend: { top: 'bottom', left: 'center'},
        tooltip: {
            trigger: 'axis',
            axisPointer: {
                type: 'cross',
                label: {
                    backgroundColor: '#6a7985'
                }
            }
        },
        grid: { bottom: 25, top: 10, left: 20, right: 10, containLabel: true }
    })
    option.xAxis[0] = Object.assign(option.xAxis[0], { type: 'category', boundaryGap: false })
    option.yAxis[0] = Object.assign(option.yAxis[0], { type: 'value', minInterval: 1 })

    option.xAxis[0].data.forEach(function (item, index) {
        this[index] = '#' + item;
    }, option.xAxis[0].data);

    option.series.forEach(function (item) {
        item.type = 'line';
        item.stack = '0';
        item.areaStyle = {  };
        item.emphasis = { focus: 'series' };
        item.smooth = false;
    });
    // Render chart finally
    renderChart(chartDivId, option);
}


function createBuildHistoryChart(chartDivId, option, i18map, small = true) {
    if (0 === option.series[0].data.length) {
        // Show "NO DATA" placeholder instead of chart if there's no data
        hide(chartDivId);
        // Use fixed 36px height
        setFrameHeight(36, chartDivId + "-no-data", false);
        return;
    }
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
        if (null != i18map) item.name = i18map[item.name].title;
    });

    if (null != i18map) {
        option.legend.data.forEach(function (item, index) {
            option.legend.data[index] = i18map[item].title;
        }, option.legend.data);
    }

    // Hide "NO DATA placeholder"
    hide(chartDivId + "-no-data");
    var innerHeight = 250;
    setFrameHeight(innerHeight, chartDivId, small);
    renderChart(chartDivId, option);
}