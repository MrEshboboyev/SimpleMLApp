using Microsoft.ML;
using PacketDotNet;
using SharpPcap;
using SimpleMLApp;

var dataPath = "C://Temp//network_traffic.csv"; // Sizning CSV faylingiz joylashgan yo‘l
var builder = new MLModelBuilder(dataPath);

// Modelni qurish va o'qitish
var model = builder.TrainAndEvaluateAll();
Console.WriteLine("✅ Model tayyor!");

var mlContext = new MLContext();
var predEngine = mlContext.Model.CreatePredictionEngine<EnhancedNetworkPacketData, PacketPrediction>(model);

using var device = new SharpPcap.LibPcap.CaptureFileReaderDevice("C://Temp//test.pcapng");
device.Open();

int count = 0;
while (device.GetNextPacket(out PacketCapture packetCapture) == GetPacketStatus.PacketRead)
{
    var raw = packetCapture.GetPacket();
    var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
    var data = PacketConverter.Convert(packet);
    if (data != null)
    {
        var prediction = predEngine.Predict(data);
        Console.WriteLine($"Packet #{++count}:" +
                          $" {(prediction.Prediction ? "Anomalous" : "Normal")} " +
                          $"({prediction.Probability:P2})" +
                          $"(Score: {prediction.Score})");
    }
}
