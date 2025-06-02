using Microsoft.ML;
using Microsoft.ML.Data;

namespace SimpleMLApp;

public class MLModelBuilder
{
    private readonly string _dataPath;
    private readonly MLContext _mlContext;

    public MLModelBuilder(string dataPath)
    {
        _dataPath = dataPath;
        _mlContext = new MLContext(seed: 1);
    }

    public ITransformer BuildAndTrainModel()
    {
        // 1. Load data
        var dataView = _mlContext.Data.LoadFromTextFile<EnhancedNetworkPacketData>(
            path: _dataPath,
            hasHeader: true,
            separatorChar: ',');

        // 2. Define column sets for transformations

        string[] numericColumns = new[]
        {
            "ProtocolNumber", "SourcePort", "DestinationPort", "TTL", "FragmentOffset",
            "TcpWindowSize", "TcpSequenceNumber", "TcpAcknowledgmentNumber",
            "TimestampSeconds", "InterPacketInterval", "FlowPacketCount", "FlowTotalBytes",
            "FlowDuration", "FlowBytesPerSecond", "FlowPacketsPerSecond", "UniqueCharacters",
            "HttpStatusCode", "HourOfDay", "DayOfWeek",
            "DnsQuestionCount", "DnsAnswerCount"
        };

        string[] booleanColumns = new[]
        {
            "IsFragmented",
            "TcpSyn", "TcpAck", "TcpFin", "TcpRst", "TcpPsh", "TcpUrg",
            "IsNightTime", "IsWeekend",
            "IsCrossBorder",
            "IsDnsQuery", "IsDnsResponse",
            "IsHttpRequest", "IsHttpResponse",
            "IsBroadcast", "IsMulticast", "IsPrivateIP", "IsLoopback",
            "IsWellKnownPort", "IsPortScanIndicator"
        };

        string[] categoricalColumns = new[]
        {
            "Protocol", "ApplicationProtocol", "SourceCountry", "DestinationCountry",
            "DnsDomain", "HttpMethod", "HttpUserAgent", "HttpHost"
        };

        string[] featureColumns = new[]
        {
            "PacketLength", "HeaderLength", "PayloadLength",
            "Protocol", "ApplicationProtocol", "ProtocolNumber",
            "SourcePort", "DestinationPort", "TTL",
            "IsFragmented", "FragmentOffset",
            "TcpSyn", "TcpAck", "TcpFin", "TcpRst", "TcpPsh", "TcpUrg",
            "TcpWindowSize", "TcpSequenceNumber", "TcpAcknowledgmentNumber",
            "TimestampSeconds", "InterPacketInterval",
            "FlowPacketCount", "FlowTotalBytes", "FlowDuration", "FlowBytesPerSecond", "FlowPacketsPerSecond",
            "PayloadEntropy", "UniqueCharacters", "AsciiRatio",
            "IsNightTime", "IsWeekend", "HourOfDay", "DayOfWeek",
            "SourceCountry", "DestinationCountry", "IsCrossBorder",
            "IsDnsQuery", "IsDnsResponse", "DnsQuestionCount", "DnsAnswerCount", "DnsDomain",
            "IsHttpRequest", "IsHttpResponse", "HttpMethod", "HttpStatusCode", "HttpUserAgent", "HttpHost",
            "IsBroadcast", "IsMulticast", "IsPrivateIP", "IsLoopback", "IsWellKnownPort", "IsPortScanIndicator"
        };

        // 3. Build pipeline

        // **E'tibor! Label ustunini MapValueToKey qilmaymiz!**
        IEstimator<ITransformer> pipeline = _mlContext.Transforms.Conversion.ConvertType("Label", outputKind: DataKind.Boolean);

        // Convert numeric columns to float
        foreach (var col in numericColumns)
        {
            pipeline = pipeline.Append(_mlContext.Transforms.Conversion.ConvertType(col, outputKind: DataKind.Single));
        }

        // Convert boolean columns to float
        foreach (var col in booleanColumns)
        {
            pipeline = pipeline.Append(_mlContext.Transforms.Conversion.ConvertType(col, outputKind: DataKind.Single));
        }

        // One-hot encode categorical columns
        foreach (var col in categoricalColumns)
        {
            pipeline = pipeline.Append(_mlContext.Transforms.Categorical.OneHotEncoding(col));
        }

        // Concatenate all features into one vector "Features"
        pipeline = pipeline.Append(_mlContext.Transforms.Concatenate("Features", featureColumns));

        // Add trainer
        pipeline = pipeline.Append(_mlContext.BinaryClassification.Trainers.FastTree());

        // 4. Train
        var model = pipeline.Fit(dataView);

        // 5. Evaluate (optional)
        var predictions = model.Transform(dataView);
        var metrics = _mlContext.BinaryClassification.Evaluate(predictions);
        Console.WriteLine($"Accuracy: {metrics.Accuracy:P2}");

        return model;
    }
}
