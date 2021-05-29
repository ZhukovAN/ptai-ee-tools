package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PluginDescriptor;
import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.model.Project;
import hudson.model.TransientProjectActionFactory;
import hudson.util.ColorPalette;
import jenkins.model.Jenkins;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import hudson.util.ChartUtil;
import hudson.util.DataSetBuilder;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.renderer.category.LineAndShapeRenderer;
import org.jfree.data.category.CategoryDataset;
import org.kohsuke.stapler.StaplerRequest;
import hudson.model.Action;
import org.kohsuke.stapler.StaplerResponse;

import java.awt.*;
import java.io.IOException;
import java.util.Collection;
import java.util.LinkedList;

@RequiredArgsConstructor
public class JenkinsAstJobReportAction implements Action {
    @NonNull
    private AbstractProject project;

    private StaplerRequest req;
    private StaplerResponse rsp;

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getUrlName() {
        return "ptai";
    }

    public void doGraph(StaplerRequest req, StaplerResponse rsp) throws IOException {
        PluginDescriptor pluginDescriptor = Jenkins.get().getDescriptorByType(PluginDescriptor.class);
        this.req = req;
        this.rsp = rsp;
        DataSetBuilder<String, ChartUtil.NumberOnlyBuildLabel> dsb = new DataSetBuilder<String, ChartUtil.NumberOnlyBuildLabel>();

        ChartUtil.generateGraph(req, rsp, createChart(dsb.build()), 400, 200);
    }


    // NVS is to be removed in the following releases
    public static JFreeChart createChart(CategoryDataset dataset)
            throws IOException {
        String title = "PT Application Inspector Vulnerability Score";
        JFreeChart chart = ChartFactory.createLineChart(title, // chart title
                "Build ID", // categoryAxisLabel
                null, // valueAxisLabel
                dataset, PlotOrientation.VERTICAL, false, // legend
                true, // tooltips
                false // urls
        );
        chart.setBackgroundPaint(Color.white);

        CategoryPlot plot = chart.getCategoryPlot();
        plot.setBackgroundPaint(Color.WHITE);
        plot.setOutlinePaint(null);
        plot.setRangeGridlinesVisible(true);
        plot.setRangeGridlinePaint(Color.black);

        CategoryAxis domainAxis = plot.getDomainAxis();
        domainAxis.setLowerMargin(0.0);
        domainAxis.setUpperMargin(0.0);

        NumberAxis rangeAxis = (NumberAxis) plot.getRangeAxis();
        rangeAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());

        LineAndShapeRenderer renderer = (LineAndShapeRenderer) plot.getRenderer();
        renderer.setBaseStroke(new BasicStroke(1.0f));
        ColorPalette.apply(renderer);

        return chart;
    }

    @Extension
    public static class Factory extends TransientProjectActionFactory {

        /**
         * This factory method is called by Jenkins to create instances of CxProjectResult for every project in the
         * system.
         */
        @Override
        public Collection<? extends Action> createFor(AbstractProject project) {
            // We don't want to add the CxProjectResult action to MatrixProject (appears as Multi-Configuration in GUI),
            // since it does not make sense to present our vulnerability graph in this level.

            /*
            if (project instanceof Project) {
                if (((Project) project).getBuildersList().get(Plugin.class) != null) {
                    LinkedList<Action> list = new LinkedList<Action>();
                    list.add(new JenkinsAstJobReportAction(project));
                    return list;
                }
            }
            */

            return null;
        }
    }
}
